"""Com WINRM_ALLOWED_HOSTS=*, o coletor aceita qualquer nome, mas só conecta em endereço interno (nunca público)."""
import socket

import pytest

from windows_rca_mcp import preflight as P
from windows_rca_mcp import server as S


def resolve_para(*enderecos):
    def r(host, port, type=None):
        return [(2, 1, 6, "", (a, 0)) for a in enderecos]
    return r


@pytest.fixture(autouse=True)
def limpo(monkeypatch):
    monkeypatch.delenv("WINRM_ALLOW_PUBLIC", raising=False)
    P.clear_address_cache()
    yield
    P.clear_address_cache()


class TestEnderecosPublicos:
    @pytest.mark.parametrize("ip", ["10.10.0.29", "172.16.5.4", "192.168.1.10", "127.0.0.1", "169.254.1.1", "100.64.0.9"])
    def test_ip_literal_interno_passa(self, ip):
        assert P.public_addresses(ip) == []

    @pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "200.221.11.100"])
    def test_ip_literal_publico_e_recusado(self, ip):
        assert P.public_addresses(ip) == [ip]

    def test_nome_que_resolve_para_interno(self):
        assert P.public_addresses("sql01.familia.local", resolver=resolve_para("10.10.0.29")) == []

    def test_nome_que_resolve_para_publico(self):
        assert P.public_addresses("www.exemplo.com", resolver=resolve_para("93.184.216.34")) == ["93.184.216.34"]

    def test_um_endereco_publico_entre_internos_basta_para_recusar(self):
        assert P.public_addresses("misto.exemplo", resolver=resolve_para("10.0.0.5", "8.8.4.4")) == ["8.8.4.4"]

    def test_ipv6_interno_e_publico(self):
        assert P.public_addresses("v6a.exemplo", resolver=resolve_para("fd00::1", "fe80::1%12")) == []
        assert P.public_addresses("v6b.exemplo", resolver=resolve_para("2001:4860:4860::8888")) == ["2001:4860:4860::8888"]

    def test_nome_que_nao_resolve_deixa_passar_e_o_dns_e_reportado_depois(self):
        def mau(*a, **k):
            raise socket.gaierror(11001, "getaddrinfo failed")
        assert P.public_addresses("nao-existe.exemplo", resolver=mau) == []

    def test_resultado_fica_em_cache(self):
        chamadas = []

        def r(host, port, type=None):
            chamadas.append(host)
            return [(2, 1, 6, "", ("10.0.0.1", 0))]
        P.public_addresses("a.exemplo", resolver=r)
        P.public_addresses("A.exemplo", resolver=r)
        assert chamadas == ["a.exemplo"]

    def test_liberacao_consciente_por_ambiente(self, monkeypatch):
        monkeypatch.setenv("WINRM_ALLOW_PUBLIC", "true")
        assert P.public_addresses("8.8.8.8") == []


class TestNoServidor:
    @pytest.fixture(autouse=True)
    def todos(self, monkeypatch):
        monkeypatch.setattr(S, "ALLOWED", ["*"])
        monkeypatch.setenv("WINRM_USER", "u")
        monkeypatch.setenv("WINRM_PASSWORD", "p")

    def test_sessao_recusa_host_publico(self):
        with pytest.raises(ValueError, match="endereço público"):
            S._session("8.8.8.8")

    def test_sessao_aceita_host_interno(self):
        assert S._session("10.20.30.40") is not None

    def test_check_winrm_recusa_host_publico(self):
        with pytest.raises(ValueError, match="endereço público"):
            S.check_winrm("1.1.1.1")

    def test_sonda_nao_abre_conexao_para_host_publico(self):
        assert S._preflight_host_ok("8.8.8.8") is False
        assert S._preflight_host_ok("10.20.30.40") is True

    def test_nome_interno_qualquer_passa_com_asterisco(self, monkeypatch):
        monkeypatch.setattr(S, "public_addresses", lambda h: [])
        assert S._host_allowed("srv-qualquer.outro.local") is True and S._preflight_host_ok("srv-qualquer.outro.local") is True

    def test_nome_que_resolve_para_publico_e_recusado(self, monkeypatch):
        monkeypatch.setattr(S, "public_addresses", lambda h: ["93.184.216.34"])
        with pytest.raises(ValueError, match="93.184.216.34"):
            S._session("www.exemplo.com")
        assert S._preflight_host_ok("www.exemplo.com") is False

    def test_liberado_por_ambiente(self, monkeypatch):
        monkeypatch.setenv("WINRM_ALLOW_PUBLIC", "true")
        assert S._session("8.8.8.8") is not None
