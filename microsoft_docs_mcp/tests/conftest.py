"""Testes do RAG: sem rede. O cache em disco vai para uma pasta temporária e a internet nunca é chamada
(as funções que a usariam são substituídas por dublês)."""
import os
import tempfile

os.environ["MS_DOCS_CACHE_DIR"] = tempfile.mkdtemp(prefix="msdocs_tests_")
os.environ.pop("MS_DOCS_OFFLINE", None)
