"""Servidor MCP "guardrails-auditor" (Grupo 3 - Guardrails para Vibe Coding).

Expone 3 tools con guardrails de filesystem:
- list_targets : lista los archivos auditables en samples/ (solo lectura).
- read_source  : lee un archivo de samples/ con numeros de linea.
- write_report : escribe el reporte final, confinado a output/.

El servidor NUNCA ejecuta el codigo auditado: solo lo lee.
El analisis de seguridad lo hace el LLM desde el cliente (src/auditor.py).
"""

import hashlib
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

BASE_DIR = Path(__file__).resolve().parent.parent
# La carpeta de samples puede sobreescribirse (la usa la webapp para auditar uploads)
SAMPLES_DIR = Path(os.getenv("AUDITOR_SAMPLES_DIR", BASE_DIR / "samples")).resolve()
OUTPUT_DIR = BASE_DIR / "output"

# Mapa de extensiones a lenguaje para dar contexto al LLM.
# Cualquier extension no listada se audita igual con lenguaje "texto".
LANGUAGE_BY_EXT = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".cpp": "cpp",
    ".cs": "csharp",
    ".rs": "rust",
    ".sh": "bash",
    ".sql": "sql",
    ".html": "html",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
}
MAX_FILE_BYTES = 100_000


def _language_of(file: Path) -> str:
    return LANGUAGE_BY_EXT.get(file.suffix.lower(), "texto")

mcp = FastMCP("guardrails-auditor")


def _safe_resolve(path: str, root: Path) -> Path:
    """Guardrail: garantiza que el path quede dentro de la carpeta permitida."""
    resolved = (root / Path(path).name).resolve()
    if not resolved.is_relative_to(root):
        raise ValueError(f"Acceso denegado: '{path}' esta fuera de {root.name}/")
    return resolved


@mcp.tool()
def list_targets() -> list[dict]:
    """Lista los archivos auditables en samples/ (lenguaje, tamano y hash)."""
    targets = []
    for file in sorted(SAMPLES_DIR.iterdir()):
        if not file.is_file() or file.name.startswith("."):
            continue
        content = file.read_bytes()
        targets.append(
            {
                "filename": file.name,
                "language": _language_of(file),
                "size_bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest()[:16],
            }
        )
    return targets


@mcp.tool()
def read_source(filename: str) -> dict:
    """Devuelve el contenido de un archivo de samples/ con numeros de linea."""
    file = _safe_resolve(filename, SAMPLES_DIR)
    if not file.is_file():
        raise ValueError(f"Archivo no encontrado: {filename}")
    if file.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"Archivo demasiado grande: {filename}")

    text = file.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    numbered = "\n".join(f"{i:4} | {line}" for i, line in enumerate(lines, 1))
    return {
        "filename": file.name,
        "language": _language_of(file),
        "line_count": len(lines),
        "numbered_code": numbered,
    }


@mcp.tool()
def write_report(markdown: str, filename: str = "reporte.md") -> dict:
    """Escribe el reporte de auditoria en output/ (unica carpeta con permiso de escritura)."""
    if not filename.endswith(".md"):
        raise ValueError("Solo se permiten reportes .md")
    file = _safe_resolve(filename, OUTPUT_DIR)
    OUTPUT_DIR.mkdir(exist_ok=True)
    file.write_text(markdown, encoding="utf-8")
    return {"path": str(file), "bytes_written": len(markdown.encode("utf-8"))}


@mcp.tool()
def write_html(html: str, filename: str = "reporte.html") -> dict:
    """Escribe el reporte en HTML en output/ (solo extension .html permitida)."""
    if not filename.endswith(".html"):
        raise ValueError("Solo se permiten reportes .html")
    file = _safe_resolve(filename, OUTPUT_DIR)
    OUTPUT_DIR.mkdir(exist_ok=True)
    file.write_text(html, encoding="utf-8")
    return {"path": str(file), "bytes_written": len(html.encode("utf-8"))}


if __name__ == "__main__":
    mcp.run()
