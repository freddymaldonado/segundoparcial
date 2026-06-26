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
from datetime import datetime, timezone
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
    agente_responde,
    agente_seguridad,
    agente_validador,
    resumen_para_reporte,
    validador_cuestiona,
)
from auditor import render_agentic_html, render_agentic_report
from client_demo import tool_result

SERVER_PATH = Path(__file__).resolve().parent / "server.py"


def _ts() -> str:
    """Timestamp legible para los logs en vivo."""
    return datetime.now(timezone.utc).astimezone().strftime("%H:%M:%S")


def _log(level: str, source: str, message: str) -> dict:
    """Construye un evento de log estilo terminal para la consola en vivo.

    level: info | tool | ok | warn | agent | report
    source: quien emite (orquestador, MCP, nombre de agente)
    """
    return {
        "type": "log",
        "level": level,
        "source": source,
        "message": message,
        "ts": _ts(),
    }


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
    model = os.getenv("OPENAI_MODEL", "gpt-5.1")
    server = StdioServerParameters(
        command=sys.executable,
        args=[str(SERVER_PATH)],
        env={**os.environ, "AUDITOR_SAMPLES_DIR": str(samples_dir)},
    )
    convo = Conversation()
    files: list[dict] = []

    yield {"type": "start", "agents": AGENT_ROSTER, "files": filenames}
    yield _log("info", "orquestador", "Sistema agentic iniciado (Cliente MCP = webapp FastAPI).")
    yield _log("info", "orquestador", f"Modelo LLM de los agentes: {model}.")
    yield _log("info", "orquestador", f"Archivos en cola de evidencia: {len(filenames)} ({', '.join(filenames)}).")
    yield _log("info", "orquestador", "Levantando servidor MCP 'guardrails-auditor' por transporte stdio...")

    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield _log("ok", "MCP", "Handshake completado. Sesion MCP establecida.")

            # Catalogo de herramientas expuestas por el servidor MCP.
            listed = await session.list_tools()
            tools_catalog = [
                {"name": t.name, "description": (t.description or "").strip().split("\n")[0]}
                for t in listed.tools
            ]
            yield {"type": "tools", "tools": tools_catalog}
            yield _log("ok", "MCP", f"{len(tools_catalog)} herramientas disponibles: {', '.join(t['name'] for t in tools_catalog)}.")

            # Mapa de hashes para enriquecer la evidencia de Recoleccion.
            yield _log("tool", "MCP", "→ list_targets()")
            targets = tool_result(await session.call_tool("list_targets", {}))
            if isinstance(targets, dict):
                targets = [targets]
            sha_by_name = {t["filename"]: t.get("sha256", "n/a") for t in targets}
            yield _log("ok", "MCP", f"✓ list_targets() → {len(targets)} archivo(s) auditable(s).")

            for idx, name in enumerate(filenames, 1):
                yield _log("info", "orquestador", f"════ Procesando archivo {idx}/{len(filenames)}: {name} ════")

                # --- Agente de Recoleccion (determinista) ---
                yield {"type": "agent", "agent": "Agente de Recoleccion", "state": "running", "file": name}
                yield _log("agent", "Agente de Recoleccion", f"Tomando evidencia de {name} via MCP.")
                yield _log("tool", "MCP", f"→ read_source(filename='{name}')")
                source = tool_result(await session.call_tool("read_source", {"filename": name}))
                yield _log("ok", "MCP", f"✓ read_source() → {source['line_count']} lineas de {source['language']}.")
                yield _log("tool", "MCP", f"→ extraer_dependencias(filename='{name}')")
                deps = tool_result(await session.call_tool("extraer_dependencias", {"filename": name}))
                declaradas = deps.get("declared", [])
                yield _log("ok", "MCP", f"✓ extraer_dependencias() → {len(declaradas)} dependencia(s): {', '.join(declaradas) or 'ninguna'}.")
                verificadas: list[dict] = []
                if declaradas:
                    yield _log("tool", "MCP", f"→ verificar_dependencias({len(declaradas)} paquetes, ecosistema='{deps['ecosistema']}')")
                    verificadas = tool_result(
                        await session.call_tool(
                            "verificar_dependencias",
                            {"paquetes": declaradas, "ecosistema": deps["ecosistema"]},
                        )
                    )
                    if isinstance(verificadas, dict):
                        verificadas = [verificadas]
                    sosp = [v["paquete"] for v in verificadas if v.get("estado") in ("sospechoso", "desconocido")]
                    yield _log(
                        "warn" if sosp else "ok",
                        "MCP",
                        f"✓ verificar_dependencias() → {len(sosp)} sospechosa(s)"
                        + (f": {', '.join(sosp)}." if sosp else "."),
                    )
                rec_msg = agente_recoleccion(source, deps, sha_by_name.get(name, "n/a"))
                convo.send(rec_msg)
                yield {"type": "message", "message": rec_msg.to_dict()}
                yield _log("agent", "Agente de Recoleccion", f"→ {rec_msg.para}: {rec_msg.resultado} (confianza {int(rec_msg.confianza*100)}%).")
                yield {"type": "agent", "agent": "Agente de Recoleccion", "state": "done", "file": name}

                # --- Seguridad + Dependencias EN PARALELO ---
                yield {"type": "agent", "agent": "Agente de Seguridad", "state": "running", "file": name}
                yield {"type": "agent", "agent": "Agente de Dependencias", "state": "running", "file": name}
                yield _log("info", "orquestador", "Despachando Agente de Seguridad y Agente de Dependencias EN PARALELO (asyncio.gather).")
                yield _log("agent", "Agente de Seguridad", f"Analizando vulnerabilidades en {name} (LLM)...")
                yield _log("agent", "Agente de Dependencias", f"Evaluando librerias de {name} (LLM + catalogo)...")
                (sec_msg, audit), (dep_msg, dep_data) = await asyncio.gather(
                    asyncio.to_thread(agente_seguridad, llm, source),
                    asyncio.to_thread(agente_dependencias, llm, deps, verificadas, source),
                )
                convo.send(sec_msg)
                yield {"type": "message", "message": sec_msg.to_dict()}
                yield _log("agent", "Agente de Seguridad", f"→ {sec_msg.para}: {sec_msg.resultado} (confianza {int(sec_msg.confianza*100)}%).")
                yield {"type": "agent", "agent": "Agente de Seguridad", "state": "done", "file": name}
                convo.send(dep_msg)
                yield {"type": "message", "message": dep_msg.to_dict()}
                yield _log("agent", "Agente de Dependencias", f"→ {dep_msg.para}: {dep_msg.resultado} (confianza {int(dep_msg.confianza*100)}%).")
                yield {"type": "agent", "agent": "Agente de Dependencias", "state": "done", "file": name}

                # --- Validador (anti-alucinacion) ---
                yield {"type": "agent", "agent": "Agente Validador", "state": "running", "file": name}
                yield _log("agent", "Agente Validador", f"Cruzando hallazgos contra el codigo real de {name} (anti-alucinacion)...")
                val_msg, val_data = await asyncio.to_thread(
                    agente_validador, llm, audit, dep_data, source
                )
                convo.send(val_msg)
                yield {"type": "message", "message": val_msg.to_dict()}
                confirmados = sum(1 for v in val_data.get("validaciones", []) if v.get("veredicto") == "CONFIRMADO")
                fp = sum(1 for v in val_data.get("validaciones", []) if v.get("veredicto") == "FALSO_POSITIVO")
                yield _log("agent", "Agente Validador", f"→ {val_msg.para}: {confirmados} confirmado(s), {fp} falso(s) positivo(s).")
                yield {"type": "agent", "agent": "Agente Validador", "state": "done", "file": name}

                # --- Back-and-forth: el Validador debate los hallazgos dudosos con su autor ---
                dudosas = [
                    v
                    for v in val_data.get("validaciones", [])
                    if v.get("veredicto") in ("FALSO_POSITIVO", "REVISION_HUMANA")
                ]
                if dudosas:
                    yield _log("info", "orquestador", f"Abriendo debate sobre {len(dudosas[:2])} hallazgo(s) dudoso(s) (ida y vuelta).")
                for v in dudosas[:2]:
                    autor = "Agente de Dependencias" if v.get("tipo") == "dependencia" else "Agente de Seguridad"
                    ref = v.get("referencia", "hallazgo")
                    # 1) El Validador cuestiona al autor.
                    q_msg = validador_cuestiona(v, name)
                    convo.send(q_msg)
                    yield {"type": "agent", "agent": autor, "state": "running", "file": name}
                    yield {"type": "message", "message": q_msg.to_dict(), "kind": "debate"}
                    yield _log("agent", "Agente Validador", f"↔ cuestiona a {autor.replace('Agente de ', '').replace('Agente ', '')} sobre '{ref}' ({v.get('veredicto')}).")
                    # 2) El autor replica con su evidencia.
                    r_msg = agente_responde(v, audit, dep_data, name)
                    convo.send(r_msg)
                    yield {"type": "message", "message": r_msg.to_dict(), "kind": "debate"}
                    yield _log("agent", autor, f"↔ responde al Validador: {r_msg.resultado}.")
                    yield {"type": "agent", "agent": autor, "state": "done", "file": name}

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
                yield _log("ok", "orquestador", f"Archivo {name} completado y agregado a la evidencia consolidada.")

            # --- Agente de Reporte ---
            yield {"type": "agent", "agent": "Agente de Reporte", "state": "running", "file": None}
            yield _log("info", "orquestador", "Consolidando evidencia validada para el Agente de Reporte...")
            yield _log("agent", "Agente de Reporte", f"Priorizando riesgos de {len(files)} archivo(s) (LLM)...")
            rep_msg, report = await asyncio.to_thread(
                agente_reporte, llm, resumen_para_reporte(files)
            )
            convo.send(rep_msg)
            yield {"type": "message", "message": rep_msg.to_dict()}
            yield _log("report", "Agente de Reporte", f"→ {rep_msg.para}: {rep_msg.resultado}.")
            yield {"type": "agent", "agent": "Agente de Reporte", "state": "done", "file": None}

            # --- Persistencia del reporte y la conversacion via MCP (guardrail de escritura) ---
            context = {
                "files": files,
                "conversation": convo.to_list(),
                "report": report,
                "agents": AGENT_ROSTER,
            }
            report_md = render_agentic_report(context)
            report_html = render_agentic_html(context)
            yield _log("tool", "MCP", "→ write_report(filename='reporte-agentic.md')")
            try:
                saved = tool_result(
                    await session.call_tool(
                        "write_report",
                        {"markdown": report_md, "filename": "reporte-agentic.md"},
                    )
                )
                yield _log("ok", "MCP", f"✓ write_report() → guardado en {saved.get('path', 'output/')}.")
                yield _log("tool", "MCP", "→ write_html(filename='reporte-agentic.html')")
                tool_result(
                    await session.call_tool(
                        "write_html",
                        {"html": report_html, "filename": "reporte-agentic.html"},
                    )
                )
                yield _log("ok", "MCP", "✓ write_html() → reporte HTML persistido.")
                yield _log("tool", "MCP", "→ registrar_conversacion(filename='conversacion-agentes.json')")
                logged = tool_result(
                    await session.call_tool(
                        "registrar_conversacion",
                        {"mensajes": convo.to_list(), "filename": "conversacion-agentes.json"},
                    )
                )
                yield _log("ok", "MCP", f"✓ registrar_conversacion() → {len(convo.to_list())} mensajes persistidos.")
            except Exception as exc:  # noqa: BLE001 - persistencia best-effort
                yield _log("warn", "MCP", f"No se pudo persistir en disco (solo lectura en server): {exc}")

            yield _log("ok", "orquestador", "Pipeline agentic finalizado. Reporte final listo para validacion humana.")
            yield {
                "type": "report",
                "report": report,
                "report_md": report_md,
                "report_html": report_html,
                "metrics": _metrics(files),
                "conversation": convo.to_list(),
                "files": [
                    {
                        "filename": f["filename"],
                        "language": f["language"],
                        "line_count": f["line_count"],
                        "sha256": f["sha256"],
                        "declared": f["declared"],
                        "verificadas": f["verificadas"],
                        "val_data": f["val_data"],
                    }
                    for f in files
                ],
            }
