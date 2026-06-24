"""Servidor MCP "guardrails-auditor" (Grupo 3 - Guardrails para Vibe Coding).

Expone tools con guardrails de filesystem que usan los agentes de IA:

Inventario / evidencia (Agente de Recoleccion):
- list_targets          : lista los archivos auditables en samples/ (solo lectura).
- read_source           : lee un archivo de samples/ con numeros de linea.
- extraer_dependencias  : extrae imports/requires declarados (ast / regex).

Verificacion determinista (Agente de Dependencias):
- verificar_dependencias: marca paquetes estandar / conocidos / sospechosos.

Sintesis (Agente de Reporte):
- write_report          : escribe el reporte .md final, confinado a output/.
- write_html            : escribe el reporte .html, confinado a output/.
- registrar_conversacion: persiste el intercambio entre agentes en output/.

El servidor NUNCA ejecuta el codigo auditado: solo lo lee y lo mide.
Los agentes (LLM) razonan; los tools miden. El analisis vive en src/agents.py.
"""

import ast
import hashlib
import json
import os
import re
import sys
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

# --- Catalogos para verificar_dependencias (deterministas, offline) ---
# Modulos de la stdlib de Python (exacto para 3.10+).
PY_STDLIB = set(getattr(sys, "stdlib_module_names", set()))

# Modulos nativos de Node.js (no requieren instalacion).
NODE_BUILTINS = {
    "fs", "path", "child_process", "crypto", "http", "https", "os", "util",
    "stream", "events", "url", "querystring", "zlib", "net", "dns", "assert",
    "buffer", "process", "readline", "cluster", "tls", "timers",
}

# Allowlist de paquetes reales muy usados (no exhaustiva: es una PoC).
KNOWN_PYPI = {
    "requests", "flask", "fastapi", "django", "numpy", "pandas", "bcrypt",
    "cryptography", "sqlalchemy", "pydantic", "openai", "mcp", "uvicorn",
    "pytest", "aiohttp", "httpx", "pyyaml", "pillow", "boto3", "redis",
    "celery", "click", "rich", "jinja2", "passlib", "argon2", "scrypt",
}
KNOWN_NPM = {
    "express", "lodash", "react", "axios", "dompurify", "validator",
    "jsonwebtoken", "bcrypt", "mongoose", "next", "vue", "moment", "chalk",
    "dotenv", "cors", "helmet", "zod", "uuid", "winston", "jest",
}

# Palabras "buzzword" tipicas de librerias alucinadas por un LLM (slopsquatting).
SUSPICIOUS_HINTS = (
    "secure", "ai", "pro", "safe", "guard", "shield", "smart", "magic",
    "auto", "ultra", "hyper", "next-gen", "quantum",
)


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
        "code": text,
    }


@mcp.tool()
def extraer_dependencias(filename: str) -> dict:
    """Extrae las dependencias declaradas en un archivo (imports/requires).

    Determinista: usa el modulo `ast` para Python y regex para JS/TS.
    Lo usa el Agente de Recoleccion para pasar evidencia al de Dependencias.
    """
    file = _safe_resolve(filename, SAMPLES_DIR)
    if not file.is_file():
        raise ValueError(f"Archivo no encontrado: {filename}")

    text = file.read_text(encoding="utf-8", errors="replace")
    language = _language_of(file)
    declared: list[str] = []

    if language == "python":
        try:
            tree = ast.parse(text)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    declared += [alias.name.split(".")[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    declared.append(node.module.split(".")[0])
        except SyntaxError:
            pass
        ecosistema = "pypi"
    elif language in ("javascript", "typescript"):
        declared += re.findall(r"""require\(\s*['"]([^'"]+)['"]\s*\)""", text)
        declared += re.findall(r"""import\s+(?:.+?\s+from\s+)?['"]([^'"]+)['"]""", text)
        ecosistema = "npm"
    else:
        ecosistema = "n/a"

    # Descartar imports relativos y normalizar paquetes con sub-rutas.
    cleaned = []
    for dep in declared:
        if dep.startswith("."):
            continue
        if not dep.startswith("@"):
            dep = dep.split("/")[0]
        cleaned.append(dep)

    return {
        "filename": file.name,
        "language": language,
        "ecosistema": ecosistema,
        "declared": sorted(set(cleaned)),
    }


@mcp.tool()
def verificar_dependencias(paquetes: list[str], ecosistema: str = "pypi") -> list[dict]:
    """Clasifica cada paquete como estandar / conocido / sospechoso / desconocido.

    Determinista y offline: catalogo local + heuristica de buzzwords contra
    librerias alucinadas (slopsquatting). Es el "medidor" del Agente de Dependencias.
    """
    resultados = []
    for paquete in paquetes:
        base = paquete.lower()
        if ecosistema == "pypi":
            if paquete in PY_STDLIB:
                estado, evidencia = "estandar", "modulo de la biblioteca estandar de Python"
            elif base in KNOWN_PYPI:
                estado, evidencia = "conocido", "paquete PyPI ampliamente utilizado"
            elif any(hint in base for hint in SUSPICIOUS_HINTS):
                estado, evidencia = "sospechoso", "nombre tipo buzzword ausente del catalogo; posible alucinacion / slopsquatting"
            else:
                estado, evidencia = "desconocido", "no esta en el catalogo local; requiere verificacion manual"
        elif ecosistema == "npm":
            if base in NODE_BUILTINS:
                estado, evidencia = "estandar", "modulo nativo de Node.js"
            elif base in KNOWN_NPM:
                estado, evidencia = "conocido", "paquete npm ampliamente utilizado"
            elif any(hint in base for hint in SUSPICIOUS_HINTS):
                estado, evidencia = "sospechoso", "nombre tipo buzzword ausente del catalogo; posible alucinacion / slopsquatting"
            else:
                estado, evidencia = "desconocido", "no esta en el catalogo local; requiere verificacion manual"
        else:
            estado, evidencia = "desconocido", f"ecosistema '{ecosistema}' no soportado"

        resultados.append(
            {"paquete": paquete, "ecosistema": ecosistema, "estado": estado, "evidencia": evidencia}
        )
    return resultados


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


@mcp.tool()
def registrar_conversacion(
    mensajes: list[dict], filename: str = "conversacion-agentes.json"
) -> dict:
    """Persiste el intercambio estructurado entre agentes en output/ (solo .json)."""
    if not filename.endswith(".json"):
        raise ValueError("Solo se permiten archivos .json")
    file = _safe_resolve(filename, OUTPUT_DIR)
    OUTPUT_DIR.mkdir(exist_ok=True)
    file.write_text(json.dumps(mensajes, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"path": str(file), "mensajes": len(mensajes)}


if __name__ == "__main__":
    mcp.run()
