#!/usr/bin/env bash
# Lanza la auditoria completa: carga .env, ejecuta el cliente MCP y abre el HTML.
set -euo pipefail

cd "$(dirname "$0")"

if [ ! -f .env ]; then
  echo "Falta el archivo .env. Copia .env.example y completa OPENAI_API_KEY."
  exit 1
fi

set -a
# shellcheck disable=SC1091
source .env
set +a

VENV_PY="../../.venv/bin/python"
if [ -x "$VENV_PY" ]; then
  PY="$VENV_PY"
else
  PY="$(command -v python3 || command -v python)"
fi

echo "Usando interprete: $PY"
echo "Abriendo la interfaz web en http://127.0.0.1:8000 ..."
"$PY" src/webapp.py
