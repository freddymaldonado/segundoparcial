"""Webapp de la PoC: interfaz drag & drop sobre el mismo flujo MCP + LLM.

Flujo por escaneo:
1. El usuario arrastra archivos y pulsa "Escanear".
2. Los archivos se guardan en un directorio temporal de uploads.
3. Se levanta el servidor MCP apuntando a ese directorio (AUDITOR_SAMPLES_DIR).
4. Por cada archivo: tool read_source -> analisis con el LLM (auditor.py).
5. Devuelve JSON con resumen por severidad + hallazgos para el frontend.
"""

import os
import shutil
import sys
import tempfile
import threading
import webbrowser
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import FileResponse
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from openai import OpenAI

from auditor import audit_file
from client_demo import tool_result

BASE_DIR = Path(__file__).resolve().parent.parent
SERVER_PATH = Path(__file__).resolve().parent / "server.py"
INDEX_HTML = BASE_DIR / "web" / "index.html"

ALLOWED_EXTENSIONS = None  # None = se acepta cualquier tipo de archivo
MAX_FILES = 10
MAX_FILE_BYTES = 100_000
SEVERITIES = ["CRITICA", "ALTA", "MEDIA", "BAJA"]

app = FastAPI(title="Guardrails para Vibe Coding - Grupo 3")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(INDEX_HTML)


@app.post("/api/scan")
async def scan(files: list[UploadFile]) -> dict:
    if not files:
        raise HTTPException(400, "No se recibieron archivos")
    if len(files) > MAX_FILES:
        raise HTTPException(400, f"Maximo {MAX_FILES} archivos por escaneo")

    upload_dir = Path(tempfile.mkdtemp(prefix="guardrails_"))
    try:
        saved = []
        for f in files:
            name = Path(f.filename or "").name
            if not name:
                raise HTTPException(400, "Nombre de archivo invalido")
            content = await f.read()
            if len(content) > MAX_FILE_BYTES:
                raise HTTPException(400, f"Archivo demasiado grande: {name}")
            (upload_dir / name).write_bytes(content)
            saved.append(name)

        results = await _audit_via_mcp(upload_dir, saved)
        return {"summary": _summarize(results), "results": results}
    finally:
        shutil.rmtree(upload_dir, ignore_errors=True)


async def _audit_via_mcp(samples_dir: Path, filenames: list[str]) -> list[dict]:
    """Audita los archivos subidos usando el servidor MCP real + LLM."""
    llm = OpenAI()
    server = StdioServerParameters(
        command=sys.executable,
        args=[str(SERVER_PATH)],
        env={**os.environ, "AUDITOR_SAMPLES_DIR": str(samples_dir)},
    )
    results = []
    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            for name in filenames:
                source = tool_result(
                    await session.call_tool("read_source", {"filename": name})
                )
                audit = audit_file(
                    llm, source["filename"], source["language"], source["numbered_code"]
                )
                results.append({
                    "filename": source["filename"],
                    "language": source["language"],
                    "code": source.get("code", ""),
                    "audit": audit,
                })
    return results


def _summarize(results: list[dict]) -> dict:
    counts = {severity: 0 for severity in SEVERITIES}
    for r in results:
        for h in r["audit"].get("hallazgos", []):
            severity = h.get("severidad", "BAJA")
            if severity in counts:
                counts[severity] += 1
    deps = sum(len(r["audit"].get("dependencias_sospechosas", [])) for r in results)
    return {
        "archivos": len(results),
        "total": sum(counts.values()),
        "por_severidad": counts,
        "dependencias_sospechosas": deps,
    }


def main() -> None:
    if not os.getenv("OPENAI_API_KEY"):
        sys.exit("ERROR: define la variable de entorno OPENAI_API_KEY")
    host, port = os.getenv("WEB_HOST", "127.0.0.1"), int(os.getenv("WEB_PORT", "8000"))
    if os.getenv("AUTO_OPEN", "1") != "0":
        threading.Timer(1.0, webbrowser.open, [f"http://{host}:{port}"]).start()
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
