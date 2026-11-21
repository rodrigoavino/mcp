// Scanner de uso de disco estilo TreeSize, compilado via Add-Type no servidor (C# 5 / .NET Framework 4.x).
// Uma única passada pela árvore, com FindFirstFileEx (sem nomes curtos, leitura em lote) e paralelismo
// nos dois primeiros níveis.
// Dois tamanhos por item: LÓGICO (como "Size" do Explorer) e EM DISCO (espaço realmente alocado):
//   - arquivo comum: o tamanho lógico arredondado para cima ao cluster do volume;
//   - arquivo compactado (NTFS) ou esparso: o tamanho alocado informado pelo sistema (GetCompressedFileSize);
//   - arquivo só-nuvem (OneDrive etc., atributos OFFLINE/RECALL): 0 em disco (o lógico continua informado).
// Opcional: contar cada arquivo com vários links físicos (hard links, ex.: WinSxS) UMA vez só.
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

public static class DiskScan
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct FindData
    {
        public uint Attr;
        public uint CreateLo, CreateHi, AccessLo, AccessHi, WriteLo, WriteHi;
        public uint SizeHi, SizeLo, Res0, Res1;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Name;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)] public string Alt;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ByHandleInfo
    {
        public uint Attributes;
        public uint CreateLo, CreateHi, AccessLo, AccessHi, WriteLo, WriteHi;
        public uint VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr FindFirstFileExW(string name, int infoLevel, out FindData data, int searchOp, IntPtr filter, int flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool FindNextFileW(IntPtr h, out FindData data);

    [DllImport("kernel32.dll")]
    static extern bool FindClose(IntPtr h);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern uint GetCompressedFileSizeW(string name, out uint high);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool GetDiskFreeSpaceW(string root, out uint sectorsPerCluster, out uint bytesPerSector, out uint freeClusters, out uint totalClusters);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetFileInformationByHandle(IntPtr h, out ByHandleInfo info);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr h);

    const uint AttrSparse = 0x200, AttrCompressed = 0x800;
    const uint AttrCloud = 0x1000 | 0x40000 | 0x400000;   // OFFLINE | RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS

    class Node
    {
        public string Name;
        public long Size, Disk, Files, Dirs, OwnSize, OwnDisk, OwnFiles;
        public List<Node> Kids;
    }

    class FileRec
    {
        public string Path;
        public long Size, Disk, Write;
    }

    class Ctx
    {
        public long Links, Denied, OtherErr, OldSize, OldDisk, OldFiles, CloudFiles, CloudBytes, DupFiles, DupBytes;
        public Dictionary<string, long[]> Ext = new Dictionary<string, long[]>();   // [lógico, arquivos, em disco]
        public List<FileRec> Top = new List<FileRec>();
        public List<string> ErrSamples = new List<string>();
    }

    class Opt
    {
        public int MaxDepth, ParDepth, TopFiles;
        public long MinBytes, OldCutoff, LimitMs, Cluster;
        public bool ByDisk, Dedupe;
        public Stopwatch Sw;
        public volatile bool Aborted;
        public ParallelOptions Po;
        public ConcurrentDictionary<string, byte> Seen = new ConcurrentDictionary<string, byte>();
    }

    static string Prefix(string p)
    {
        if (p.StartsWith("\\\\?\\")) return p;
        if (p.StartsWith("\\\\")) return "\\\\?\\UNC\\" + p.Substring(2);
        return "\\\\?\\" + p;
    }

    static string Join(string d, string n)
    {
        return d.EndsWith("\\") ? d + n : d + "\\" + n;
    }

    // valor usado para ordenar e calcular percentuais: lógico (padrão) ou em disco
    static long Metric(Opt o, long size, long disk)
    {
        return o.ByDisk ? disk : size;
    }

    static void Err(Ctx c, string dir, int code)
    {
        if (code == 5) c.Denied++; else c.OtherErr++;
        if (c.ErrSamples.Count < 10) c.ErrSamples.Add(dir + " (erro " + code + ")");
    }

    static void Prune(List<FileRec> l, int keep, bool byDisk)
    {
        if (byDisk) l.Sort((a, b) => b.Disk.CompareTo(a.Disk)); else l.Sort((a, b) => b.Size.CompareTo(a.Size));
        if (l.Count > keep) l.RemoveRange(keep, l.Count - keep);
    }

    // tamanho alocado de um arquivo (ver o cabeçalho): sem chamada extra para arquivos comuns
    static long OnDisk(string dir, string name, uint attr, long logical, Opt o)
    {
        if ((attr & AttrCloud) != 0) return 0;
        if ((attr & (AttrCompressed | AttrSparse)) != 0)
        {
            uint hi;
            uint lo = GetCompressedFileSizeW(Prefix(Join(dir, name)), out hi);
            if (!(lo == 0xFFFFFFFF && Marshal.GetLastWin32Error() != 0)) return ((long)hi << 32) | lo;
        }
        if (logical == 0 || o.Cluster <= 0) return logical;
        return ((logical + o.Cluster - 1) / o.Cluster) * o.Cluster;
    }

    // true se este arquivo tem vários links físicos e outro link JÁ foi contado
    static bool IsRepeatedHardLink(string dir, string name, Opt o)
    {
        IntPtr h = CreateFileW(Prefix(Join(dir, name)), 0, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
        if (h == new IntPtr(-1)) return false;
        try
        {
            ByHandleInfo bi;
            if (!GetFileInformationByHandle(h, out bi) || bi.Links < 2) return false;
            string key = bi.VolumeSerial.ToString("x8") + ":" + bi.IndexHigh.ToString("x8") + bi.IndexLow.ToString("x8");
            return !o.Seen.TryAdd(key, 1);
        }
        finally { CloseHandle(h); }
    }

    static void Account(Ctx c, Opt o, string dir, string name, long size, long disk, long write)
    {
        int dot = name.LastIndexOf('.');
        string ext = (dot > 0 && dot < name.Length - 1) ? name.Substring(dot).ToLowerInvariant() : "(sem extensao)";
        long[] e;
        if (!c.Ext.TryGetValue(ext, out e))
        {
            if (c.Ext.Count > 5000) ext = "(outras)";
            if (!c.Ext.TryGetValue(ext, out e)) { e = new long[3]; c.Ext[ext] = e; }
        }
        e[0] += size; e[1]++; e[2] += disk;
        if (write < o.OldCutoff) { c.OldSize += size; c.OldDisk += disk; c.OldFiles++; }
        if (Metric(o, size, disk) >= o.MinBytes)
        {
            FileRec r = new FileRec();
            r.Path = Join(dir, name); r.Size = size; r.Disk = disk; r.Write = write;
            c.Top.Add(r);
            if (c.Top.Count > 4 * o.TopFiles + 200) Prune(c.Top, o.TopFiles, o.ByDisk);
        }
    }

    static void Merge(Ctx dst, Ctx src, Opt o)
    {
        dst.Links += src.Links; dst.Denied += src.Denied; dst.OtherErr += src.OtherErr;
        dst.OldSize += src.OldSize; dst.OldDisk += src.OldDisk; dst.OldFiles += src.OldFiles;
        dst.CloudFiles += src.CloudFiles; dst.CloudBytes += src.CloudBytes; dst.DupFiles += src.DupFiles; dst.DupBytes += src.DupBytes;
        foreach (KeyValuePair<string, long[]> kv in src.Ext)
        {
            long[] e;
            if (!dst.Ext.TryGetValue(kv.Key, out e)) dst.Ext[kv.Key] = kv.Value;
            else { e[0] += kv.Value[0]; e[1] += kv.Value[1]; e[2] += kv.Value[2]; }
        }
        dst.Top.AddRange(src.Top);
        if (dst.Top.Count > 4 * o.TopFiles + 200) Prune(dst.Top, o.TopFiles, o.ByDisk);
        foreach (string s in src.ErrSamples) if (dst.ErrSamples.Count < 10) dst.ErrSamples.Add(s);
    }

    static Node Walk(string dir, int depth, Ctx c, Opt o)
    {
        Node n = new Node();
        if (o.Aborted) return n;
        if (o.Sw.ElapsedMilliseconds > o.LimitMs) { o.Aborted = true; return n; }
        if (depth > 150) { Err(c, dir, -2); return n; }

        FindData fd;
        string pattern = Prefix(dir) + (dir.EndsWith("\\") ? "*" : "\\*");
        IntPtr h = FindFirstFileExW(pattern, 1, out fd, 0, IntPtr.Zero, 2); // Basic + LARGE_FETCH
        if (h == new IntPtr(-1)) { Err(c, dir, Marshal.GetLastWin32Error()); return n; }

        List<string> subs = null;
        try
        {
            do
            {
                if ((fd.Attr & 0x10) != 0)
                {
                    if (fd.Name == "." || fd.Name == "..") continue;
                    if ((fd.Attr & 0x400) != 0) { c.Links++; continue; } // junction/symlink: não segue
                    if (subs == null) subs = new List<string>();
                    subs.Add(fd.Name);
                }
                else
                {
                    long size = ((long)fd.SizeHi << 32) | fd.SizeLo;
                    long write = ((long)fd.WriteHi << 32) | fd.WriteLo;
                    long disk = OnDisk(dir, fd.Name, fd.Attr, size, o);
                    if ((fd.Attr & AttrCloud) != 0) { c.CloudFiles++; c.CloudBytes += size; }
                    else if (o.Dedupe && IsRepeatedHardLink(dir, fd.Name, o)) { c.DupFiles++; c.DupBytes += size; continue; }
                    n.OwnSize += size; n.OwnDisk += disk; n.OwnFiles++;
                    Account(c, o, dir, fd.Name, size, disk, write);
                }
            } while (FindNextFileW(h, out fd));
        }
        finally { FindClose(h); }

        n.Size = n.OwnSize; n.Disk = n.OwnDisk; n.Files = n.OwnFiles;
        if (subs != null)
        {
            Node[] res = new Node[subs.Count];
            if (depth < o.ParDepth && subs.Count > 1)
            {
                object gate = new object();
                Parallel.For(0, subs.Count, o.Po, delegate(int i)
                {
                    Ctx cc = new Ctx();
                    try { res[i] = Walk(Join(dir, subs[i]), depth + 1, cc, o); }
                    catch (Exception) { res[i] = new Node(); Err(cc, Join(dir, subs[i]), -1); }
                    lock (gate) { Merge(c, cc, o); }
                });
            }
            else
            {
                for (int i = 0; i < subs.Count; i++) res[i] = Walk(Join(dir, subs[i]), depth + 1, c, o);
            }
            for (int i = 0; i < subs.Count; i++)
            {
                Node r = res[i];
                r.Name = subs[i];
                n.Size += r.Size; n.Disk += r.Disk; n.Files += r.Files; n.Dirs += 1 + r.Dirs;
                if (depth + 1 <= o.MaxDepth)
                {
                    if (n.Kids == null) n.Kids = new List<Node>();
                    n.Kids.Add(r);
                }
            }
        }
        return n;
    }

    // ---------- saída JSON (ASCII puro, cultura invariante) ----------
    static string Gb(long b)
    {
        return Math.Round(b / 1073741824.0, 2).ToString(CultureInfo.InvariantCulture);
    }

    static string Iso(long ft)
    {
        try { return ft > 0 ? DateTime.FromFileTimeUtc(ft).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture) : ""; }
        catch (Exception) { return ""; }
    }

    static void Str(StringBuilder sb, string s)
    {
        sb.Append('"');
        foreach (char ch in s)
        {
            if (ch == '"') sb.Append("\\\"");
            else if (ch == '\\') sb.Append("\\\\");
            else if (ch < 32 || ch > 126) sb.Append("\\u").Append(((int)ch).ToString("x4"));
            else sb.Append(ch);
        }
        sb.Append('"');
    }

    static string Pct(long part, long total)
    {
        return total > 0 ? Math.Round(100.0 * part / total, 1).ToString(CultureInfo.InvariantCulture) : "0";
    }

    static void WriteNode(StringBuilder sb, Node n, int topKids, long total, Opt o)
    {
        sb.Append("{\"name\":"); Str(sb, n.Name ?? "");
        sb.Append(",\"size_gb\":").Append(Gb(n.Size)).Append(",\"disk_gb\":").Append(Gb(n.Disk));
        sb.Append(",\"size_bytes\":").Append(n.Size).Append(",\"disk_bytes\":").Append(n.Disk);
        sb.Append(",\"pct\":").Append(Pct(Metric(o, n.Size, n.Disk), total));
        sb.Append(",\"files\":").Append(n.Files).Append(",\"dirs\":").Append(n.Dirs);
        if (n.OwnFiles > 0) sb.Append(",\"files_here\":").Append(n.OwnFiles).Append(",\"size_here_gb\":").Append(Gb(n.OwnSize)).Append(",\"disk_here_gb\":").Append(Gb(n.OwnDisk));
        if (n.Kids != null && n.Kids.Count > 0)
        {
            if (o.ByDisk) n.Kids.Sort((a, b) => b.Disk.CompareTo(a.Disk)); else n.Kids.Sort((a, b) => b.Size.CompareTo(a.Size));
            int k = Math.Min(topKids, n.Kids.Count);
            sb.Append(",\"children\":[");
            for (int i = 0; i < k; i++)
            {
                if (i > 0) sb.Append(',');
                WriteNode(sb, n.Kids[i], topKids, total, o);
            }
            sb.Append(']');
            if (n.Kids.Count > k)
            {
                long rest = 0, restDisk = 0, restFiles = 0;
                for (int i = k; i < n.Kids.Count; i++) { rest += n.Kids[i].Size; restDisk += n.Kids[i].Disk; restFiles += n.Kids[i].Files; }
                sb.Append(",\"others\":{\"count\":").Append(n.Kids.Count - k).Append(",\"size_gb\":").Append(Gb(rest))
                  .Append(",\"disk_gb\":").Append(Gb(restDisk)).Append(",\"pct\":").Append(Pct(Metric(o, rest, restDisk), total))
                  .Append(",\"files\":").Append(restFiles).Append('}');
            }
        }
        sb.Append('}');
    }

    public static string Run(string root, int maxDepth, int topKids, int topFiles, long minBytes, int threads, int timeoutSec, int oldDays, bool byDisk, bool dedupe)
    {
        root = root.Replace('/', '\\');
        Opt o = new Opt();
        o.MaxDepth = maxDepth; o.ParDepth = 2; o.TopFiles = topFiles; o.MinBytes = minBytes;
        o.OldCutoff = DateTime.UtcNow.AddDays(-oldDays).ToFileTimeUtc();
        o.Sw = Stopwatch.StartNew(); o.LimitMs = timeoutSec * 1000L;
        o.Po = new ParallelOptions(); o.Po.MaxDegreeOfParallelism = threads;
        o.ByDisk = byDisk; o.Dedupe = dedupe;
        uint spc, bps, fc, tc;
        o.Cluster = 4096;
        try
        {
            string r = System.IO.Path.GetPathRoot(root);
            if (!String.IsNullOrEmpty(r) && GetDiskFreeSpaceW(r, out spc, out bps, out fc, out tc) && spc > 0 && bps > 0) o.Cluster = (long)spc * bps;
        }
        catch (Exception) { }

        Ctx c = new Ctx();
        Node tree = Walk(root, 0, c, o);
        tree.Name = root;
        Prune(c.Top, topFiles, byDisk);
        long total = Metric(o, tree.Size, tree.Disk);

        StringBuilder sb = new StringBuilder(64 * 1024);
        sb.Append("{\"path\":"); Str(sb, root);
        sb.Append(",\"elapsed_s\":").Append(Math.Round(o.Sw.Elapsed.TotalSeconds, 1).ToString(CultureInfo.InvariantCulture));
        sb.Append(",\"partial\":").Append(o.Aborted ? "true" : "false");
        sb.Append(",\"measure\":\"").Append(byDisk ? "disk" : "logical").Append('"');
        sb.Append(",\"cluster_bytes\":").Append(o.Cluster);
        sb.Append(",\"total_gb\":").Append(Gb(tree.Size)).Append(",\"total_disk_gb\":").Append(Gb(tree.Disk));
        sb.Append(",\"total_bytes\":").Append(tree.Size).Append(",\"total_disk_bytes\":").Append(tree.Disk);
        sb.Append(",\"files\":").Append(tree.Files).Append(",\"dirs\":").Append(tree.Dirs);
        sb.Append(",\"links_skipped\":").Append(c.Links);
        sb.Append(",\"cloud_only\":{\"files\":").Append(c.CloudFiles).Append(",\"logical_gb\":").Append(Gb(c.CloudBytes)).Append('}');
        sb.Append(",\"hardlinks\":{\"deduplicated\":").Append(dedupe ? "true" : "false")
          .Append(",\"repeated_files_skipped\":").Append(c.DupFiles).Append(",\"repeated_gb_skipped\":").Append(Gb(c.DupBytes)).Append('}');
        sb.Append(",\"access_denied\":").Append(c.Denied).Append(",\"other_errors\":").Append(c.OtherErr);
        sb.Append(",\"error_samples\":[");
        for (int i = 0; i < c.ErrSamples.Count; i++) { if (i > 0) sb.Append(','); Str(sb, c.ErrSamples[i]); }
        sb.Append("],\"tree\":"); WriteNode(sb, tree, topKids, total, o);

        sb.Append(",\"top_files\":[");
        for (int i = 0; i < c.Top.Count; i++)
        {
            if (i > 0) sb.Append(',');
            sb.Append("{\"path\":"); Str(sb, c.Top[i].Path);
            sb.Append(",\"size_gb\":").Append(Gb(c.Top[i].Size)).Append(",\"disk_gb\":").Append(Gb(c.Top[i].Disk));
            sb.Append(",\"modified\":\"").Append(Iso(c.Top[i].Write)).Append("\"}");
        }
        sb.Append("],\"by_extension\":[");
        List<KeyValuePair<string, long[]>> ex = new List<KeyValuePair<string, long[]>>(c.Ext);
        if (byDisk) ex.Sort((a, b) => b.Value[2].CompareTo(a.Value[2])); else ex.Sort((a, b) => b.Value[0].CompareTo(a.Value[0]));
        for (int i = 0; i < Math.Min(15, ex.Count); i++)
        {
            if (i > 0) sb.Append(',');
            sb.Append("{\"ext\":"); Str(sb, ex[i].Key);
            sb.Append(",\"size_gb\":").Append(Gb(ex[i].Value[0])).Append(",\"disk_gb\":").Append(Gb(ex[i].Value[2]))
              .Append(",\"files\":").Append(ex[i].Value[1]).Append('}');
        }
        sb.Append("],\"old_data\":{\"days\":").Append(oldDays);
        sb.Append(",\"size_gb\":").Append(Gb(c.OldSize)).Append(",\"disk_gb\":").Append(Gb(c.OldDisk)).Append(",\"files\":").Append(c.OldFiles).Append("}}");
        return sb.ToString();
    }
}
