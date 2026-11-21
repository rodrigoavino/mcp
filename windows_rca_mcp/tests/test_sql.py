"""get_sql_diagnostics: consultas fixas (checagem estática), sinais, formato e entradas (sem SQL Server e sem WinRM).

Importante: não há um servidor SQL no laboratório e nenhum parser de T-SQL é usado aqui. Estes testes garantem que as
consultas são FIXAS, de leitura e sem parâmetros concatenados; a sintaxe e as colunas só são confirmadas numa instância real."""
import inspect
import re

import pytest

from windows_rca_mcp import server as S

H = "fastmcp.familia.local"


def _sem_strings_e_comentarios(sql: str) -> str:
    sql = re.sub(r"--[^\n]*", " ", sql)
    return re.sub(r"'(?:[^']|'')*'", "''", sql)


class TestConsultasFixas:
    def test_todas_as_secoes_tem_consulta(self):
        assert set(S.SQL_DEFAULT_SECTIONS) <= set(S.SQL_QUERIES)
        assert set(S.SQL_ALL_SECTIONS) == {"overview", "databases", "files", "backups", "jobs", "blocking", "waits", "resources", "errorlog", "availability"}

    @pytest.mark.parametrize("nome", sorted(S.SQL_QUERIES))
    def test_so_leitura(self, nome):
        sql = _sem_strings_e_comentarios(S.SQL_QUERIES[nome]).upper()
        for proibido in ("INSERT ", "UPDATE ", "DELETE ", "DROP ", "ALTER ", "CREATE ", "TRUNCATE ", "MERGE ", "GRANT ", "REVOKE ",
                         "DENY ", "SHUTDOWN", "RECONFIGURE", "XP_CMDSHELL", "OPENROWSET", "OPENQUERY", "OPENDATASOURCE", "BULK ",
                         "INTO #", "SELECT INTO", "KILL ", "BACKUP ", "RESTORE ", "DBCC ", "SP_CONFIGURE"):
            assert proibido not in sql, f"{nome}: {proibido}"

    @pytest.mark.parametrize("nome", sorted(S.SQL_QUERIES))
    def test_um_unico_comando(self, nome):
        sql = _sem_strings_e_comentarios(S.SQL_QUERIES[nome]).strip().rstrip(";")
        assert ";" not in sql, nome                                   # sem encadear comandos
        assert sql.upper().startswith(("SELECT", "EXEC SYS.SP_READERRORLOG")), nome

    def test_o_unico_exec_e_o_log_de_erros(self):
        execs = [n for n, q in S.SQL_QUERIES.items() if re.search(r"(?i)\bEXEC\b", _sem_strings_e_comentarios(q))]
        assert execs == ["errorlog"]
        assert S.SQL_QUERIES["errorlog"] == "EXEC sys.sp_readerrorlog 0, 1, N'Error';"

    @pytest.mark.parametrize("nome", sorted(S.SQL_QUERIES))
    def test_parenteses_e_aspas_balanceados(self, nome):
        sql = S.SQL_QUERIES[nome]
        limpo = _sem_strings_e_comentarios(sql)
        assert limpo.count("(") == limpo.count(")"), nome
        assert sql.replace("''", "").count("'") % 2 == 0, nome

    def test_parametros_so_os_permitidos(self):
        usados = set()
        for q in S.SQL_QUERIES.values():
            usados |= set(re.findall(r"(?<![@\w])@(\w+)", _sem_strings_e_comentarios(q))) - {"VERSION"}
        assert usados <= {"db", "hours", "text"}

    def test_consultas_nao_sao_montadas_com_entrada_do_usuario(self):
        src = inspect.getsource(S.get_sql_diagnostics)
        # banco, horas e texto vão como parâmetros SQL (@db, @hours, @text), não dentro do texto da consulta
        assert "SQL_QUERIES[n]" in src and "database" not in src.split("queries =")[1].split("script =")[0]

    def test_esperas_de_fundo_ficam_de_fora_da_lista_de_waits(self):
        w = S.SQL_QUERIES["waits"]
        assert "__BENIGN__" not in w and "'SLEEP_TASK'" in w and "NOT IN (" in w
        assert "PAGEIOLATCH_SH" not in w and "LCK_M_X" not in w        # esperas reais NÃO são excluídas


class TestScript:
    def test_conecta_na_instancia_local_com_autenticacao_integrada(self):
        ps = S.PS_SQL
        assert "Integrated Security=SSPI" in ps and "ApplicationIntent=ReadOnly" in ps
        assert "Password" not in ps and "User ID" not in ps and "Pwd" not in ps
        assert "Server=$srv" in ps and "'.'" in ps                                 # só a instância local

    def test_parametros_sql_nao_concatenacao(self):
        assert "Parameters.AddWithValue('@db'" in S.PS_SQL and "Parameters.AddWithValue('@hours'" in S.PS_SQL

    def test_so_consulta_se_ha_servico_de_instancia(self):
        assert "MSSQLSERVER" in S.PS_SQL and "SqlFound=$false" in S.PS_SQL

    def test_cada_secao_falha_sozinha(self):
        assert "catch { $sections[$s] = [pscustomobject]@{ Error=" in S.PS_SQL


class TestEntradas:
    def test_secao_invalida(self):
        with pytest.raises(ValueError, match="seção inválida"):
            S.get_sql_diagnostics(H, sections=["databases", "DROP"])

    @pytest.mark.parametrize("ruim", ["a;b", "a'b", "", "x" * 129, "a b", "a\\b"])
    def test_instancia_invalida(self, ruim):
        with pytest.raises(ValueError, match="instance"):
            S.get_sql_diagnostics(H, instance=ruim)

    @pytest.mark.parametrize("ruim", ["a;b", "a'b", "a$(x)", "", "x" * 129])
    def test_database_invalido(self, ruim):
        with pytest.raises(ValueError, match="database"):
            S.get_sql_diagnostics(H, database=ruim)

    def test_secoes_padrao_e_sem_repeticao(self):
        assert S._sql_sections(None) == list(S.SQL_DEFAULT_SECTIONS)
        assert S._sql_sections(["jobs", "jobs", "waits"]) == ["jobs", "waits"]

    def test_script_gerado_so_traz_as_secoes_pedidas(self, monkeypatch):
        capturado = {}
        monkeypatch.setattr(S, "_ps", lambda host, script, timeout=60: capturado.setdefault("s", script) and {"SqlFound": False})
        S.get_sql_diagnostics(H, sections=["jobs"], database="Vendas", job_hours=9999)
        s = capturado["s"]
        assert "$Q['jobs']" in s and "$Q['databases']" not in s
        assert "$hours = 168" in s and "$db = 'Vendas'" in s and "$withText = 0" in s


class TestSinaisEFormato:
    def _res(self, **sec):
        return {"SqlFound": True, "Connected": True, "Instances": {"Service": "MSSQLSERVER", "Instance": "MSSQLSERVER", "Status": "Running"}, "Sections": sec}

    def test_sem_servico_de_sql_devolve_como_veio(self):
        r = {"SqlFound": False, "Message": "Nenhum serviço"}
        assert S._sql_shape(r, H) == r

    def test_servico_parado_ou_falha_de_conexao_nao_gera_sinais(self):
        r = {"SqlFound": True, "Connected": False, "Message": "O serviço da instância está Stopped", "Instances": []}
        assert "status" not in S._sql_shape(r, H)

    def test_sem_sinais(self):
        r = S._sql_shape(self._res(databases=[{"Name": "Vendas", "State": "ONLINE", "AutoShrink": False, "AutoClose": False}],
                                   backups=[{"DatabaseName": "Vendas", "State": "ONLINE", "LastFull": "x", "DaysSinceLastFull": 1}]), H)
        assert r["status"] == S.SEM and r["findings"] == ["Nenhum sinal encontrado."]

    def test_sinais_com_limiar_a_vista(self):
        r = S._sql_shape(self._res(
            databases=[{"Name": "A", "State": "RECOVERY_PENDING", "AutoShrink": True, "AutoClose": True}, {"Name": "B", "State": "ONLINE"}],
            backups=[{"DatabaseName": "B", "State": "ONLINE", "LastFull": "x", "DaysSinceLastFull": 12},
                     {"DatabaseName": "C", "State": "ONLINE", "LastFull": None, "DaysSinceLastFull": None}],
            jobs=[{"JobName": "J"}],
            blocking=[{"SessionId": 5, "BlockingSessionId": 9, "WaitMs": 45000}, {"SessionId": 6, "BlockingSessionId": 0, "WaitMs": 0}]), H)
        t = " | ".join(r["findings"])
        assert r["status"] == S.SIG
        for esperado in ("fora de ONLINE: A (RECOVERY_PENDING)", "Auto-shrink ligado em: A", "Auto-close ligado em: A",
                         "Sem nenhum backup completo", "C", "mais de 7 dias (limiar do projeto): B (12 d)",
                         "falha no período", "1 sessão(ões) bloqueada(s) há mais de 30 s (limiar do projeto)"):
            assert esperado in t, esperado

    def test_secao_sem_permissao_vira_verificacao_incompleta(self):
        r = S._sql_shape(self._res(waits={"Error": "VIEW SERVER STATE permission was denied"}, databases=[]), H)
        assert r["status"] == S.INC and "waits" in r["findings"][0] and "VIEW SERVER STATE" in r["findings"][0]

    def test_texto_do_sql_e_do_log_sao_mascarados(self):
        r = S._sql_shape(self._res(blocking=[{"SessionId": 1, "BlockingSessionId": 2, "WaitMs": 1, "SqlText": "EXEC x @password = 'abc' password=zzz"}],
                                   errorlog=[{"Text": "Login failed; pwd=123"}]), H)
        assert "zzz" not in r["Sections"]["blocking"][0]["SqlText"] and "123" not in r["Sections"]["errorlog"][0]["Text"]

    def test_linha_unica_vira_lista(self):
        r = S._sql_shape(self._res(overview={"ServerName": "X"}), H)
        assert r["Sections"]["overview"] == [{"ServerName": "X"}]

    def test_erro_passa_sem_alteracao(self):
        assert S._sql_shape({"error": "x", "host": "h"}, H) == {"error": "x", "host": "h"}

    def test_sem_julgamento_no_codigo(self):
        src = (inspect.getsource(S._sql_signals) + inspect.getsource(S.get_sql_diagnostics)).lower()
        src = re.sub(r"(sem|nem) [a-zçãé ]*recomenda\w+", "", src)       # as negações ("sem recomendação") são o oposto de julgar
        for termo in ("recomend", "deve ser", "inadequad", "perigos"):
            assert termo not in src
