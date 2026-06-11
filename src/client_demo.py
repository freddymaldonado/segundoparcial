"""Cliente de demo: orquesta la auditoria completa via MCP real (stdio).

Flujo agentic de la PoC:
1. Levanta el servidor MCP guardrails-auditor como subproceso (stdio).
2. Llama al tool list_targets para descubrir los archivos de samples/.
3. Por cada archivo: read_source -> analisis con el LLM (auditor.py).
4. Renderiza el reporte en Markdown y HTML y lo persiste con los tools del servidor.
5. Abre el reporte HTML en el navegador (si la variable AUTO_OPEN no es "0").
"""

import asyncio
import json
import os
import sys
import webbrowser
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from openai import OpenAI

from auditor import audit_file, render_html, render_report

SERVER_PATH = Path(__file__).resolve().parent / "server.py"


def tool_result(result) -> dict | list:
    """Extrae el JSON devuelto por un tool MCP.

    FastMCP serializa una lista como varios items de contenido,
    por eso se parsean todos y se devuelve lista solo si hay mas de uno.
    """
    items = [json.loads(c.text) for c in result.content]
    return items[0] if len(items) == 1 else items


async def main() -> None:
    if not os.getenv("OPENAI_API_KEY"):
        sys.exit("ERROR: define la variable de entorno OPENAI_API_KEY")

    llm = OpenAI()
    server = StdioServerParameters(command=sys.executable, args=[str(SERVER_PATH)])

    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("[1/4] Conectado al servidor MCP guardrails-auditor")

            targets = tool_result(await session.call_tool("list_targets", {}))
            if isinstance(targets, dict):
                targets = [targets]
            print(f"[2/4] Archivos a auditar: {[t['filename'] for t in targets]}")

            results = []
            for target in targets:
                source = tool_result(
                    await session.call_tool("read_source", {"filename": target["filename"]})
                )
                print(f"[3/4] Auditando {source['filename']} con el LLM...")
                audit = audit_file(
                    llm, source["filename"], source["language"], source["numbered_code"]
                )
                results.append({"filename": source["filename"], "audit": audit})

            report_md = render_report(results)
            written_md = tool_result(
                await session.call_tool("write_report", {"markdown": report_md})
            )
            report_html = render_html(results)
            written_html = tool_result(
                await session.call_tool("write_html", {"html": report_html})
            )
            print(f"[4/4] Reportes generados:\n  - {written_md['path']}\n  - {written_html['path']}")

            if os.getenv("AUTO_OPEN", "1") != "0":
                webbrowser.open(Path(written_html["path"]).as_uri())


if __name__ == "__main__":
    asyncio.run(main())
