"""Testes do coletor: só funções puras, SEM WinRM, SEM rede e SEM credenciais.

O ambiente é fixado ANTES de importar o servidor: allowlist de teste e um .env inexistente (para nunca ler credenciais reais)."""
import os
import tempfile

os.environ["WINRM_ALLOWED_HOSTS"] = "*.familia.local,localhost"
os.environ["WINRM_ENV_FILE"] = os.path.join(tempfile.gettempdir(), "nao-existe-windows-ops.env")
for k in ("WINRM_USER", "WINRM_PASSWORD", "WINRM_HTTP_HOSTS"):
    os.environ.pop(k, None)
