// Scanner de uso de disco estilo TreeSize, compilado via Add-Type no servidor (C# 5 / .NET Framework 4.x).
// Uma única passada pela árvore, com FindFirstFileEx (sem nomes curtos, leitura em lote) e paralelismo
// nos dois primeiros níveis. Tamanhos são lógicos (como "Size" do Explorer), não "tamanho em disco".
using System;
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

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr FindFirstFileExW(string name, int infoLevel, out FindData data, int searchOp, IntPtr filter, int flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool FindNextFileW(IntPtr h, out FindData data);

    [DllImport("kernel32.dll")]
    static extern bool FindClose(IntPtr h);

    class Node
    {
        public string Name;
        public long Size, Files, Dirs, OwnSize, OwnFiles;
        public List<Node> Kids;
    }

    class FileRec
    {
        public string Path;
        public long Size, Write;
    }

    class Ctx
    {
        public long Links, Denied, OtherErr, OldSize, OldFiles;
        public Dictionary<string, long[]> Ext = new Dictionary<string, long[]>();
        public List<FileRec> Top = new List<FileRec>();
        public List<string> ErrSamples = new List<string>();
    }

    class Opt
    {
        public int MaxDepth, ParDepth, TopFiles;
        public long MinBytes, OldCutoff, LimitMs;
        public Stopwatch Sw;
        public volatile bool Aborted;
        public ParallelOptions Po;
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

    static void Err(Ctx c, string dir, int code)
    {
        if (code == 5) c.Denied++; else c.OtherErr++;
        if (c.ErrSamples.Count < 10) c.ErrSamples.Add(dir + " (erro " + code + ")");
    }

    static void Prune(List<FileRec> l, int keep)
    {
        l.Sort((a, b) => b.Size.CompareTo(a.Size));
        if (l.Count > keep) l.RemoveRange(keep, l.Count - keep);
    }

    static void Account(Ctx c, Opt o, string dir, string name, long size, long write)
    {
        int dot = name.LastIndexOf('.');
        string ext = (dot > 0 && dot < name.Length - 1) ? name.Substring(dot).ToLowerInvariant() : "(sem extensao)";
        long[] e;
        if (!c.Ext.TryGetValue(ext, out e))
        {
            if (c.Ext.Count > 5000) ext = "(outras)";
            if (!c.Ext.TryGetValue(ext, out e)) { e = new long[2]; c.Ext[ext] = e; }
        }
        e[0] += size; e[1]++;
        if (write < o.OldCutoff) { c.OldSize += size; c.OldFiles++; }
        if (size >= o.MinBytes)
        {
            FileRec r = new FileRec();
            r.Path = Join(dir, name); r.Size = size; r.Write = write;
            c.Top.Add(r);
            if (c.Top.Count > 4 * o.TopFiles + 200) Prune(c.Top, o.TopFiles);
        }
    }

    static void Merge(Ctx dst, Ctx src, Opt o)
    {
        dst.Links += src.Links; dst.Denied += src.Denied; dst.OtherErr += src.OtherErr;
        dst.OldSize += src.OldSize; dst.OldFiles += src.OldFiles;
        foreach (KeyValuePair<string, long[]> kv in src.Ext)
        {
            long[] e;
            if (!dst.Ext.TryGetValue(kv.Key, out e)) dst.Ext[kv.Key] = kv.Value;
            else { e[0] += kv.Value[0]; e[1] += kv.Value[1]; }
        }
        dst.Top.AddRange(src.Top);
        if (dst.Top.Count > 4 * o.TopFiles + 200) Prune(dst.Top, o.TopFiles);
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
                    n.OwnSize += size; n.OwnFiles++;
                    Account(c, o, dir, fd.Name, size, write);
                }
            } while (FindNextFileW(h, out fd));
        }
        finally { FindClose(h); }

        n.Size = n.OwnSize; n.Files = n.OwnFiles;
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
                n.Size += r.Size; n.Files += r.Files; n.Dirs += 1 + r.Dirs;
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

    static void WriteNode(StringBuilder sb, Node n, int topKids, long total)
    {
        sb.Append("{\"name\":"); Str(sb, n.Name ?? "");
        sb.Append(",\"size_gb\":").Append(Gb(n.Size));
        sb.Append(",\"pct\":").Append(total > 0 ? Math.Round(100.0 * n.Size / total, 1).ToString(CultureInfo.InvariantCulture) : "0");
        sb.Append(",\"files\":").Append(n.Files).Append(",\"dirs\":").Append(n.Dirs);
        if (n.OwnFiles > 0) sb.Append(",\"files_here\":").Append(n.OwnFiles).Append(",\"size_here_gb\":").Append(Gb(n.OwnSize));
        if (n.Kids != null && n.Kids.Count > 0)
        {
            n.Kids.Sort((a, b) => b.Size.CompareTo(a.Size));
            int k = Math.Min(topKids, n.Kids.Count);
            sb.Append(",\"children\":[");
            for (int i = 0; i < k; i++)
            {
                if (i > 0) sb.Append(',');
                WriteNode(sb, n.Kids[i], topKids, total);
            }
            sb.Append(']');
            if (n.Kids.Count > k)
            {
                long rest = 0;
                for (int i = k; i < n.Kids.Count; i++) rest += n.Kids[i].Size;
                sb.Append(",\"others\":{\"count\":").Append(n.Kids.Count - k).Append(",\"size_gb\":").Append(Gb(rest)).Append('}');
            }
        }
        sb.Append('}');
    }

    public static string Run(string root, int maxDepth, int topKids, int topFiles, long minBytes, int threads, int timeoutSec, int oldDays)
    {
        root = root.Replace('/', '\\');
        Opt o = new Opt();
        o.MaxDepth = maxDepth; o.ParDepth = 2; o.TopFiles = topFiles; o.MinBytes = minBytes;
        o.OldCutoff = DateTime.UtcNow.AddDays(-oldDays).ToFileTimeUtc();
        o.Sw = Stopwatch.StartNew(); o.LimitMs = timeoutSec * 1000L;
        o.Po = new ParallelOptions(); o.Po.MaxDegreeOfParallelism = threads;

        Ctx c = new Ctx();
        Node tree = Walk(root, 0, c, o);
        tree.Name = root;
        Prune(c.Top, topFiles);

        StringBuilder sb = new StringBuilder(64 * 1024);
        sb.Append("{\"path\":"); Str(sb, root);
        sb.Append(",\"elapsed_s\":").Append(Math.Round(o.Sw.Elapsed.TotalSeconds, 1).ToString(CultureInfo.InvariantCulture));
        sb.Append(",\"partial\":").Append(o.Aborted ? "true" : "false");
        sb.Append(",\"total_gb\":").Append(Gb(tree.Size));
        sb.Append(",\"files\":").Append(tree.Files).Append(",\"dirs\":").Append(tree.Dirs);
        sb.Append(",\"links_skipped\":").Append(c.Links);
        sb.Append(",\"access_denied\":").Append(c.Denied).Append(",\"other_errors\":").Append(c.OtherErr);
        sb.Append(",\"error_samples\":[");
        for (int i = 0; i < c.ErrSamples.Count; i++) { if (i > 0) sb.Append(','); Str(sb, c.ErrSamples[i]); }
        sb.Append("],\"tree\":"); WriteNode(sb, tree, topKids, tree.Size);

        sb.Append(",\"top_files\":[");
        for (int i = 0; i < c.Top.Count; i++)
        {
            if (i > 0) sb.Append(',');
            sb.Append("{\"path\":"); Str(sb, c.Top[i].Path);
            sb.Append(",\"size_gb\":").Append(Gb(c.Top[i].Size));
            sb.Append(",\"modified\":\"").Append(Iso(c.Top[i].Write)).Append("\"}");
        }
        sb.Append("],\"by_extension\":[");
        List<KeyValuePair<string, long[]>> ex = new List<KeyValuePair<string, long[]>>(c.Ext);
        ex.Sort((a, b) => b.Value[0].CompareTo(a.Value[0]));
        for (int i = 0; i < Math.Min(15, ex.Count); i++)
        {
            if (i > 0) sb.Append(',');
            sb.Append("{\"ext\":"); Str(sb, ex[i].Key);
            sb.Append(",\"size_gb\":").Append(Gb(ex[i].Value[0])).Append(",\"files\":").Append(ex[i].Value[1]).Append('}');
        }
        sb.Append("],\"old_data\":{\"days\":").Append(oldDays);
        sb.Append(",\"size_gb\":").Append(Gb(c.OldSize)).Append(",\"files\":").Append(c.OldFiles).Append("}}");
        return sb.ToString();
    }
}
