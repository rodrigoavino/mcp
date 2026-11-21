"""get_dns_cache e resolve_dns_name: validações e normalização (sem WinRM e sem consultar DNS)."""
import pytest

from windows_rca_mcp import server as S


class TestResolveDnsName:
    @pytest.mark.parametrize("nome", ["dc-w25-03.familia.local", "_ldap._tcp.dc._msdcs.familia.local", "10.11.0.3",
                                      "3.0.11.10.in-addr.arpa"])
    def test_aceita_nomes_validos(self, nome):
        assert S.DNS_NAME_RE.match(nome)

    @pytest.mark.parametrize("nome", ["a b", "a;b", "a'b", "a$b", "a|b", "*.familia.local", "", "x" * 254])
    def test_recusa_nomes_perigosos_ou_curinga(self, nome):
        assert not S.DNS_NAME_RE.match(nome)

    def test_tipo_de_registro_invalido(self):
        with pytest.raises(ValueError):
            S.resolve_dns_name("fastmcp.familia.local", "a.familia.local", "ANY")

    def test_nome_invalido_recusado_antes_de_conectar(self):
        with pytest.raises(ValueError):
            S.resolve_dns_name("fastmcp.familia.local", "a;b")

    def test_servidor_dns_invalido(self):
        with pytest.raises(ValueError):
            S.resolve_dns_name("fastmcp.familia.local", "a.familia.local", "A", "10.0.0.1; calc")

    def test_tipos_aceitos(self):
        assert set(S.DNS_RECORD_TYPES) == {"A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT"}


class TestDnsCache:
    def test_filtro_com_curinga_e_validado(self):
        assert S.DNS_FILTER_RE.match("*.familia.local")
        assert not S.DNS_FILTER_RE.match("a;b")
        with pytest.raises(ValueError):
            S.get_dns_cache("fastmcp.familia.local", "a;b")

    def test_nomes_legiveis_para_tipo_e_status(self):
        res = {"Total": 3, "Matched": 3, "Entries": [{"Type": 1, "Status": 0}, {"Type": 28, "Status": 9003}, {"Type": 99, "Status": 123}]}
        r = S._dns_cache_shape(res, None, 100)
        assert [e["TypeName"] for e in r["Entries"]] == ["A", "AAAA", "99"]
        assert r["Entries"][0]["StatusName"] == "Success"
        assert r["Entries"][1]["StatusName"].startswith("DNS_ERROR_RCODE_NAME_ERROR")
        assert r["Entries"][2]["StatusName"] == "123"   # desconhecido: fica numérico, nada inventado

    def test_entrada_unica_vira_lista_e_truncamento_e_informado(self):
        r = S._dns_cache_shape({"Total": 9, "Matched": 5, "Entries": {"Type": 1, "Status": 0}}, "*", 1)
        assert isinstance(r["Entries"], list) and r["Truncated"] is True and r["Filter"] == "*"

    def test_erro_passa_sem_alteracao(self):
        assert S._dns_cache_shape({"error": "x", "host": "h"}, None, 10) == {"error": "x", "host": "h"}

    def test_truncamento_considera_o_filtro_e_nao_o_total(self):
        # 6 entradas no cache, 1 casa com o filtro e 1 foi devolvida: não houve corte
        r = S._dns_cache_shape({"Total": 6, "Matched": 1, "Entries": [{"Type": 1, "Status": 0}]}, "*.familia.local", 5)
        assert r["Truncated"] is False
