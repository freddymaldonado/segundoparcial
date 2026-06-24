"""Orquestador del sistema agentic (Grupo 3 - Guardrails para Vibe Coding).

Coordina a los 5 agentes sobre el MISMO servidor MCP real (stdio). Por cada
archivo recorre el flujo:

  Recoleccion --> Seguridad --> Validador --> Reporte
              \\-> Dependencias -/

Cada paso emite un AgentMessage estructurado al bus `Conversation`. Al final
se genera el reporte agentic (Markdown + HTML) y se persiste la conversacion,
todo a traves de los tools del servidor MCP.

Uso:
    export OPENAI_API_KEY="sk-..."
    python src/orchestrator.py
"""

import asyncio
import os
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from openai import OpenAI

from agents import (
    AGENT_ROSTER,
    Conversation,
    agente_dependencias,
    agente_recoleccion,
    agente_reporte,
    agente_seguridad,
    agente_validador,
    resumen_para_reporte,
)
from auditor import render_agentic_html, render_agentic_report
from client_demo import tool_result

SERVER_PATH = Path(__file__).resolve().parent / "server.py"


async def run() -> None:
    if not os.getenv("OPENAI_API_KEY"):
        sys.exit("ERROR: define la variable de entorno OPENAI_API_KEY")

    llm = OpenAI()
    server = StdioServerParameters(command=sys.executable, args=[str(SERVER_PATH)])
    convo = Conversation()

    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("== Sistema agentic de Guardrails - Grupo 3 ==")
            print("[MCP] Conectado al servidor guardrails-auditor\n")

            targets = tool_result(await session.call_tool("list_targets", {}))
            if isinstance(targets, dict):
                targets = [targets]
            print(f"[Recoleccion] Archivos descubiertos: {[t['filename'] for t in targets]}\n")

            files: list[dict] = []
            for target in targets:
                name = target["filename"]
                source = tool_result(await session.call_tool("read_source", {"filename": name}))
                deps = tool_result(await session.call_tool("extraer_dependencias", {"filename": name}))
                verificadas = []
                if deps.get("declared"):
                    verificadas = tool_result(
                        await session.call_tool(
                            "verificar_dependencias",
                            {"paquetes": deps["declared"], "ecosistema": deps["ecosistema"]},
                        )
                    )
                    if isinstance(verificadas, dict):
                        verificadas = [verificadas]

                # 1. Recoleccion (determinista)
                convo.send(agente_recoleccion(source, deps, target["sha256"]))

                # 2. Seguridad (LLM)
                sec_msg, audit = agente_seguridad(llm, source)
                convo.send(sec_msg)
                print(f"[Seguridad] {name}: {len(audit.get('hallazgos', []))} hallazgos")

                # 3. Dependencias (LLM + catalogo)
                dep_msg, dep_data = agente_dependencias(llm, deps, verificadas, source)
                convo.send(dep_msg)

                # 4. Validador (LLM, anti-alucinacion)
                val_msg, val_data = agente_validador(llm, audit, dep_data, source)
                convo.send(val_msg)
                print(f"[Validador] {name}: {val_msg.resultado}\n")

                files.append(
                    {
                        "filename": name,
                        "language": source["language"],
                        "line_count": source["line_count"],
                        "sha256": target["sha256"],
                        "declared": deps.get("declared", []),
                        "verificadas": verificadas,
                        "audit": audit,
                        "dep_data": dep_data,
                        "val_data": val_data,
                    }
                )

            # 5. Reporte (LLM)
            rep_msg, report = agente_reporte(llm, resumen_para_reporte(files))
            convo.send(rep_msg)
            print(f"[Reporte] {rep_msg.resultado}\n")

            context = {
                "files": files,
                "conversation": convo.to_list(),
                "report": report,
                "agents": AGENT_ROSTER,
            }

            report_md = render_agentic_report(context)
            written_md = tool_result(
                await session.call_tool(
                    "write_report", {"markdown": report_md, "filename": "reporte-agentic.md"}
                )
            )
            report_html = render_agentic_html(context)
            written_html = tool_result(
                await session.call_tool(
                    "write_html", {"html": report_html, "filename": "reporte-agentic.html"}
                )
            )
            written_convo = tool_result(
                await session.call_tool(
                    "registrar_conversacion", {"mensajes": convo.to_list()}
                )
            )

            print("== Reporte final generado ==")
            print(f"  - {written_md['path']}")
            print(f"  - {written_html['path']}")
            print(f"  - {written_convo['path']} ({written_convo['mensajes']} mensajes)")


if __name__ == "__main__":
    asyncio.run(run())
