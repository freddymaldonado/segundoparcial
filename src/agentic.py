"""Pipeline agentic en streaming para la webapp (Parte II).

Ejecuta el flujo multi-agente sobre el servidor MCP real y va emitiendo eventos
a medida que cada agente actua, para que la UI los muestre EN VIVO. Los agentes
de Seguridad y Dependencias corren en paralelo (asyncio) porque son independientes
y ambos alimentan al Validador.

Eventos emitidos (cada uno es un dict que la webapp serializa como NDJSON):
- {"type": "start", "agents": [...], "files": [...]}
- {"type": "agent", "agent": "...", "state": "running|done", "file": "..."}
- {"type": "message", "message": {...AgentMessage...}}
- {"type": "file_done", "file": "...", "audit": {...}, "dep_data": {...}, "val_data": {...}}
- {"type": "report", "report": {...}, "report_md": "...", "metrics": {...}}
- {"type": "error", "detail": "..."}
"""

import asyncio
import os
import sys
from collections.abc import AsyncIterator
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
from auditor import render_agentic_report
from client_demo import tool_result

SERVER_PATH = Path(__file__).resolve().parent / "server.py"


def _metrics(files: list[dict]) -> dict:
    """Metricas agregadas para la cabecera del reporte agentic."""
    sev = {"CRITICA": 0, "ALTA": 0, "MEDIA": 0, "BAJA": 0}
    confirmados = 0
    falsos = 0
    for f in files:
        for h in f["audit"].get("hallazgos", []):
            s = h.get("severidad", "BAJA")
            if s in sev:
                sev[s] += 1
        for v in f["val_data"].get("validaciones", []):
            if v.get("veredicto") == "CONFIRMADO":
                confirmados += 1
            elif v.get("veredicto") == "FALSO_POSITIVO":
                falsos += 1
    deps = sum(
        1
        for f in files
        for d in f["dep_data"].get("dependencias", [])
        if d.get("estado") in ("sospechoso", "desconocido")
    )
    return {
        "archivos": len(files),
        "total": sum(sev.values()),
        "por_severidad": sev,
        "dependencias_sospechosas": deps,
        "confirmados": confirmados,
        "falsos_positivos": falsos,
    }


async def run_agentic_stream(samples_dir: Path, filenames: list[str]) -> AsyncIterator[dict]:
    """Ejecuta el flujo multi-agente emitiendo eventos en vivo."""
    if not os.getenv("OPENAI_API_KEY"):
        yield {"type": "error", "detail": "OPENAI_API_KEY no esta definido"}
        return

    llm = OpenAI()
    server = StdioServerParameters(
        command=sys.executable,
        args=[str(SERVER_PATH)],
        env={**os.environ, "AUDITOR_SAMPLES_DIR": str(samples_dir)},
    )
    convo = Conversation()
    files: list[dict] = []

    yield {"type": "start", "agents": AGENT_ROSTER, "files": filenames}

    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Mapa de hashes para enriquecer la evidencia de Recoleccion.
            targets = tool_result(await session.call_tool("list_targets", {}))
            if isinstance(targets, dict):
                targets = [targets]
            sha_by_name = {t["filename"]: t.get("sha256", "n/a") for t in targets}

            for name in filenames:
                # --- Agente de Recoleccion (determinista) ---
                yield {"type": "agent", "agent": "Agente de Recoleccion", "state": "running", "file": name}
                source = tool_result(await session.call_tool("read_source", {"filename": name}))
                deps = tool_result(await session.call_tool("extraer_dependencias", {"filename": name}))
                verificadas: list[dict] = []
                if deps.get("declared"):
                    verificadas = tool_result(
                        await session.call_tool(
                            "verificar_dependencias",
                            {"paquetes": deps["declared"], "ecosistema": deps["ecosistema"]},
                        )
                    )
                    if isinstance(verificadas, dict):
                        verificadas = [verificadas]
                rec_msg = agente_recoleccion(source, deps, sha_by_name.get(name, "n/a"))
                convo.send(rec_msg)
                yield {"type": "message", "message": rec_msg.to_dict()}
                yield {"type": "agent", "agent": "Agente de Recoleccion", "state": "done", "file": name}

                # --- Seguridad + Dependencias EN PARALELO ---
                yield {"type": "agent", "agent": "Agente de Seguridad", "state": "running", "file": name}
                yield {"type": "agent", "agent": "Agente de Dependencias", "state": "running", "file": name}
                (sec_msg, audit), (dep_msg, dep_data) = await asyncio.gather(
                    asyncio.to_thread(agente_seguridad, llm, source),
                    asyncio.to_thread(agente_dependencias, llm, deps, verificadas, source),
                )
                convo.send(sec_msg)
                yield {"type": "message", "message": sec_msg.to_dict()}
                yield {"type": "agent", "agent": "Agente de Seguridad", "state": "done", "file": name}
                convo.send(dep_msg)
                yield {"type": "message", "message": dep_msg.to_dict()}
                yield {"type": "agent", "agent": "Agente de Dependencias", "state": "done", "file": name}

                # --- Validador (anti-alucinacion) ---
                yield {"type": "agent", "agent": "Agente Validador", "state": "running", "file": name}
                val_msg, val_data = await asyncio.to_thread(
                    agente_validador, llm, audit, dep_data, source
                )
                convo.send(val_msg)
                yield {"type": "message", "message": val_msg.to_dict()}
                yield {"type": "agent", "agent": "Agente Validador", "state": "done", "file": name}

                files.append(
                    {
                        "filename": name,
                        "language": source["language"],
                        "line_count": source["line_count"],
                        "sha256": sha_by_name.get(name, "n/a"),
                        "declared": deps.get("declared", []),
                        "verificadas": verificadas,
                        "audit": audit,
                        "dep_data": dep_data,
                        "val_data": val_data,
                    }
                )
                yield {
                    "type": "file_done",
                    "file": name,
                    "language": source["language"],
                    "code": source.get("code", ""),
                    "audit": audit,
                    "dep_data": dep_data,
                    "val_data": val_data,
                }

            # --- Agente de Reporte ---
            yield {"type": "agent", "agent": "Agente de Reporte", "state": "running", "file": None}
            rep_msg, report = await asyncio.to_thread(
                agente_reporte, llm, resumen_para_reporte(files)
            )
            convo.send(rep_msg)
            yield {"type": "message", "message": rep_msg.to_dict()}
            yield {"type": "agent", "agent": "Agente de Reporte", "state": "done", "file": None}

            context = {
                "files": files,
                "conversation": convo.to_list(),
                "report": report,
                "agents": AGENT_ROSTER,
            }
            yield {
                "type": "report",
                "report": report,
                "report_md": render_agentic_report(context),
                "metrics": _metrics(files),
                "conversation": convo.to_list(),
            }
