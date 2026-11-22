"""Carregamento do .env de ajustes do RAG (sem rede)."""
import importlib
import os

import pytest

import microsoft_docs_mcp as M

VARS = ("MS_DOCS_OFFLINE", "MS_DOCS_PAGE_TTL_DAYS", "MS_DOCS_SEARCH_TTL_DAYS", "MS_DOCS_CACHE_DIR", "MCP_PORT", "MS_DOCS_ENV_FILE")


@pytest.fixture(autouse=True)
def ambiente_limpo(monkeypatch, tmp_path):
    for v in VARS:
        monkeypatch.delenv(v, raising=False)
    monkeypatch.chdir(tmp_path)               # a pasta de trabalho do teste não tem .env
    yield
    for v in VARS:                            # o load_env grava em os.environ: não vaza para os outros testes
        os.environ.pop(v, None)
    from microsoft_docs_mcp import grounding
    importlib.reload(grounding)


class TestLoadEnv:
    def test_sem_arquivo_nao_faz_nada(self):
        assert M.load_env() is None

    def test_le_o_env_da_pasta_de_trabalho(self, tmp_path):
        (tmp_path / ".env").write_text("MS_DOCS_PAGE_TTL_DAYS=3\nMCP_PORT=9001\n", encoding="utf-8")
        assert M.load_env() == str(tmp_path / ".env")
        assert os.environ["MS_DOCS_PAGE_TTL_DAYS"] == "3" and os.environ["MCP_PORT"] == "9001"

    def test_caminho_por_variavel_de_sistema(self, tmp_path, monkeypatch):
        outro = tmp_path / "config" / "rag.env"
        outro.parent.mkdir()
        outro.write_text("MS_DOCS_SEARCH_TTL_DAYS=5\n", encoding="utf-8")
        monkeypatch.setenv("MS_DOCS_ENV_FILE", str(outro))
        assert M.load_env() == str(outro) and os.environ["MS_DOCS_SEARCH_TTL_DAYS"] == "5"

    def test_variavel_do_sistema_vence_a_do_arquivo(self, tmp_path, monkeypatch):
        (tmp_path / ".env").write_text("MS_DOCS_PAGE_TTL_DAYS=3\n", encoding="utf-8")
        monkeypatch.setenv("MS_DOCS_PAGE_TTL_DAYS", "30")
        M.load_env()
        assert os.environ["MS_DOCS_PAGE_TTL_DAYS"] == "30"

    def test_procura_so_na_pasta_de_trabalho_e_nao_nas_pastas_de_cima(self, tmp_path, monkeypatch):
        (tmp_path / ".env").write_text("MCP_PORT=9001\n", encoding="utf-8")
        filho = tmp_path / "filho"
        filho.mkdir()
        monkeypatch.chdir(filho)
        assert M.load_env() is None and "MCP_PORT" not in os.environ

    def test_arquivo_apontado_que_nao_existe_nao_derruba(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MS_DOCS_ENV_FILE", str(tmp_path / "nao-existe.env"))
        assert M.load_env() is None


class TestValoresChegamAoCache:
    def test_ttl_e_offline_vem_do_env(self, tmp_path):
        (tmp_path / ".env").write_text("MS_DOCS_PAGE_TTL_DAYS=3\nMS_DOCS_SEARCH_TTL_DAYS=2\nMS_DOCS_OFFLINE=true\n"
                                       f"MS_DOCS_CACHE_DIR={tmp_path / 'cache'}\n", encoding="utf-8")
        M.load_env()
        from microsoft_docs_mcp import grounding
        importlib.reload(grounding)
        assert grounding.PAGE_TTL_S == 3 * 86400 and grounding.SEARCH_TTL_S == 2 * 86400
        assert grounding.OFFLINE is True and str(grounding.CACHE_DIR) == str(tmp_path / "cache")

    def test_padroes_sem_env(self):
        from microsoft_docs_mcp import grounding
        importlib.reload(grounding)
        assert grounding.PAGE_TTL_S == 7 * 86400 and grounding.SEARCH_TTL_S == 86400 and grounding.OFFLINE is False


class TestEnvExample:
    def test_modelo_traz_todas_as_variaveis_do_codigo(self):
        from pathlib import Path
        src = "".join(p.read_text(encoding="utf-8") for p in (Path(M.__file__).parent).glob("*.py"))
        usadas = {v for v in ("MS_DOCS_OFFLINE", "MS_DOCS_CACHE_DIR", "MS_DOCS_PAGE_TTL_DAYS", "MS_DOCS_SEARCH_TTL_DAYS", "MCP_TRANSPORT",
                              "MCP_HOST", "MCP_PORT", "MCP_AUTH_TOKEN", "MCP_ALLOW_INSECURE_LOOPBACK") if v in src}
        modelo = (Path(M.__file__).parents[2] / ".env.example").read_text(encoding="utf-8")
        assert usadas and all(v in modelo for v in usadas)
        assert "MS_DOCS_ENV_FILE" in modelo and "MS_DOCS_ENV_FILE" in src
