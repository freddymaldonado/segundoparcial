"""Auditor LLM: analisis de seguridad 100% con IA (sin motores estaticos).

Recibe el codigo que el servidor MCP leyo y le pide al LLM un analisis
defensivo estructurado en JSON. Tambien renderiza el reporte Markdown final.
"""

import json
import os

from openai import OpenAI

MODEL = os.getenv("OPENAI_MODEL", "gpt-5.1")

SYSTEM_PROMPT = """Eres un auditor defensivo de codigo generado por IA (Blue Team).
Tu unica mision es revisar codigo fuente y reportar riesgos. Reglas:

1. NO expliques como explotar las vulnerabilidades paso a paso.
2. Clasifica cada hallazgo con severidad: CRITICA, ALTA, MEDIA o BAJA.
3. Detecta dependencias falsas, inexistentes o sospechosas (alucinadas por un LLM).
4. Propone siempre una reescritura segura concreta.
5. Distingue evidencia observada en el codigo de cualquier inferencia tuya.
6. Si algo requiere validacion humana, dilo explicitamente.

Responde SOLO con un objeto JSON valido con este esquema exacto:
{
  "resumen": "una o dos frases sobre el estado de seguridad del archivo",
  "hallazgos": [
    {
      "titulo": "nombre corto del fallo",
      "severidad": "CRITICA | ALTA | MEDIA | BAJA",
      "linea": numero_de_linea,
      "cwe": "CWE-XX si aplica",
      "evidencia": "fragmento exacto del codigo",
      "explicacion": "por que es un riesgo, en tono defensivo",
      "reescritura_segura": "codigo o indicacion concreta de como corregirlo"
    }
  ],
  "dependencias_sospechosas": [
    {"paquete": "nombre", "motivo": "por que parece inexistente o riesgosa"}
  ],
  "requiere_validacion_humana": ["puntos donde el analista debe verificar"]
}"""


def audit_file(client: OpenAI, filename: str, language: str, numbered_code: str) -> dict:
    """Envia un archivo al LLM y devuelve el analisis estructurado."""
    user_prompt = (
        f"Audita el siguiente archivo generado por IA.\n"
        f"Archivo: {filename}\nLenguaje: {language}\n\n"
        f"Codigo (con numeros de linea):\n```\n{numbered_code}\n```"
    )
    response = client.chat.completions.create(
        model=MODEL,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
    )
    return json.loads(response.choices[0].message.content)


def render_report(results: list[dict]) -> str:
    """Convierte los analisis del LLM en el reporte Markdown final."""
    total = sum(len(r["audit"].get("hallazgos", [])) for r in results)
    criticos = sum(
        1
        for r in results
        for h in r["audit"].get("hallazgos", [])
        if h.get("severidad") == "CRITICA"
    )
    deps = sum(len(r["audit"].get("dependencias_sospechosas", [])) for r in results)

    lines = [
        "# Reporte de Auditoria IA - Guardrails para Vibe Coding (Grupo 3)",
        "",
        f"Modelo utilizado: `{MODEL}`",
        "",
        "## Metricas",
        "",
        f"- Archivos analizados: {len(results)}",
        f"- Hallazgos totales: {total}",
        f"- Hallazgos criticos: {criticos}",
        f"- Dependencias sospechosas: {deps}",
        "",
    ]

    for r in results:
        audit = r["audit"]
        lines += [f"## Archivo: `{r['filename']}`", "", f"> {audit.get('resumen', '')}", ""]

        for h in audit.get("hallazgos", []):
            lines += [
                f"### [{h.get('severidad')}] {h.get('titulo')} (linea {h.get('linea')}, {h.get('cwe', 'N/A')})",
                "",
                f"- Evidencia: `{h.get('evidencia')}`",
                f"- Riesgo: {h.get('explicacion')}",
                f"- Reescritura segura: {h.get('reescritura_segura')}",
                "",
            ]

        if audit.get("dependencias_sospechosas"):
            lines.append("### Dependencias sospechosas")
            lines.append("")
            for d in audit["dependencias_sospechosas"]:
                lines.append(f"- `{d.get('paquete')}`: {d.get('motivo')}")
            lines.append("")

        if audit.get("requiere_validacion_humana"):
            lines.append("### Requiere validacion humana")
            lines.append("")
            for punto in audit["requiere_validacion_humana"]:
                lines.append(f"- {punto}")
            lines.append("")

    lines += [
        "---",
        "",
        "*La IA recomienda, el humano valida. Reporte generado de forma automatizada*",
        "*via servidor MCP guardrails-auditor + LLM. PoC academica defensiva.*",
        "",
    ]
    return "\n".join(lines)


SEVERITY_COLORS = {
    "CRITICA": "#dc2626",
    "ALTA": "#ea580c",
    "MEDIA": "#ca8a04",
    "BAJA": "#16a34a",
}


def _badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#475569")
    return f'<span class="badge" style="background:{color}">{severity}</span>'


def _esc(text: str) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def render_html(results: list[dict]) -> str:
    """Genera una pagina HTML autocontenida con el resultado de la auditoria."""
    total = sum(len(r["audit"].get("hallazgos", [])) for r in results)
    criticos = sum(
        1
        for r in results
        for h in r["audit"].get("hallazgos", [])
        if h.get("severidad") == "CRITICA"
    )
    deps = sum(len(r["audit"].get("dependencias_sospechosas", [])) for r in results)

    css = """
    :root { color-scheme: light; }
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           background: #f8fafc; color: #0f172a; margin: 0; padding: 2rem; line-height: 1.55; }
    .wrap { max-width: 960px; margin: 0 auto; }
    header { background: linear-gradient(135deg, #0f172a, #1e293b); color: white;
             padding: 2rem; border-radius: 14px; margin-bottom: 1.5rem; }
    header h1 { margin: 0 0 .5rem 0; font-size: 1.6rem; }
    header p  { margin: 0; opacity: .85; }
    .metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem;
               margin-bottom: 1.5rem; }
    .metric { background: white; padding: 1rem; border-radius: 12px;
              box-shadow: 0 1px 3px rgba(0,0,0,.06); text-align: center; }
    .metric .n { font-size: 1.8rem; font-weight: 700; color: #0f172a; }
    .metric .l { font-size: .8rem; text-transform: uppercase;
                 letter-spacing: .04em; color: #64748b; }
    .metric.critical .n { color: #dc2626; }
    .file { background: white; padding: 1.5rem; border-radius: 12px;
            margin-bottom: 1.25rem; box-shadow: 0 1px 3px rgba(0,0,0,.06); }
    .file h2 { margin-top: 0; font-size: 1.15rem; font-family: ui-monospace, monospace;
               color: #1e293b; }
    .summary { color: #475569; font-style: italic; margin-bottom: 1rem; }
    .finding { border-left: 4px solid #cbd5e1; padding: .85rem 1rem;
               margin-bottom: .75rem; background: #f8fafc; border-radius: 0 8px 8px 0; }
    .finding h3 { margin: 0 0 .5rem 0; font-size: .98rem; }
    .badge { color: white; padding: .15rem .55rem; border-radius: 999px;
             font-size: .72rem; font-weight: 700; margin-right: .5rem; letter-spacing: .03em; }
    code { background: #e2e8f0; padding: .12rem .4rem; border-radius: 4px;
           font-size: .82rem; word-break: break-word; }
    .line { color: #64748b; font-size: .82rem; }
    .field { margin: .3rem 0; font-size: .92rem; }
    .field b { color: #334155; }
    .deps, .human { margin-top: 1rem; padding-top: .75rem;
                    border-top: 1px solid #e2e8f0; }
    .deps h4, .human h4 { margin: 0 0 .4rem 0; font-size: .9rem;
                          text-transform: uppercase; letter-spacing: .04em; color: #64748b; }
    footer { text-align: center; color: #94a3b8; font-size: .82rem;
             margin-top: 2rem; padding: 1rem; }
    """

    parts: list[str] = [
        "<!doctype html><html lang='es'><head><meta charset='utf-8'>",
        "<title>Auditoria IA - Grupo 3</title>",
        f"<style>{css}</style></head><body><div class='wrap'>",
        "<header>",
        "<h1>Guardrails para Vibe Coding - Reporte de Auditoria IA</h1>",
        f"<p>Grupo 3 &middot; Modelo: <code>{_esc(MODEL)}</code> &middot;"
        " Servidor MCP guardrails-auditor</p>",
        "</header>",
        "<section class='metrics'>",
        f"<div class='metric'><div class='n'>{len(results)}</div>"
        "<div class='l'>Archivos</div></div>",
        f"<div class='metric'><div class='n'>{total}</div>"
        "<div class='l'>Hallazgos</div></div>",
        f"<div class='metric critical'><div class='n'>{criticos}</div>"
        "<div class='l'>Criticos</div></div>",
        f"<div class='metric'><div class='n'>{deps}</div>"
        "<div class='l'>Deps sospechosas</div></div>",
        "</section>",
    ]

    for r in results:
        audit = r["audit"]
        parts.append(f"<article class='file'><h2>{_esc(r['filename'])}</h2>")
        parts.append(f"<p class='summary'>{_esc(audit.get('resumen', ''))}</p>")

        for h in audit.get("hallazgos", []):
            parts.append("<div class='finding'>")
            parts.append(
                f"<h3>{_badge(h.get('severidad', 'BAJA'))}{_esc(h.get('titulo', ''))}"
                f" <span class='line'>(linea {_esc(h.get('linea', '?'))},"
                f" {_esc(h.get('cwe', 'N/A'))})</span></h3>"
            )
            parts.append(
                f"<div class='field'><b>Evidencia:</b> <code>{_esc(h.get('evidencia', ''))}</code></div>"
            )
            parts.append(
                f"<div class='field'><b>Riesgo:</b> {_esc(h.get('explicacion', ''))}</div>"
            )
            parts.append(
                f"<div class='field'><b>Reescritura segura:</b> {_esc(h.get('reescritura_segura', ''))}</div>"
            )
            parts.append("</div>")

        if audit.get("dependencias_sospechosas"):
            parts.append("<div class='deps'><h4>Dependencias sospechosas</h4><ul>")
            for d in audit["dependencias_sospechosas"]:
                parts.append(
                    f"<li><code>{_esc(d.get('paquete', ''))}</code> &mdash;"
                    f" {_esc(d.get('motivo', ''))}</li>"
                )
            parts.append("</ul></div>")

        if audit.get("requiere_validacion_humana"):
            parts.append("<div class='human'><h4>Requiere validacion humana</h4><ul>")
            for punto in audit["requiere_validacion_humana"]:
                parts.append(f"<li>{_esc(punto)}</li>")
            parts.append("</ul></div>")

        parts.append("</article>")

    parts.append(
        "<footer>La IA recomienda, el humano valida &middot;"
        " PoC academica defensiva &middot; Grupo 3</footer>"
    )
    parts.append("</div></body></html>")
    return "".join(parts)


# =========================================================================== #
# Reporte del sistema AGENTIC (Parte II): incluye la conversacion entre        #
# agentes, hallazgos validados, riesgos priorizados y limitaciones.            #
# =========================================================================== #

VEREDICTO_ICON = {
    "CONFIRMADO": "[OK] CONFIRMADO",
    "FALSO_POSITIVO": "[x] FALSO POSITIVO",
    "REVISION_HUMANA": "[?] REVISION HUMANA",
}


def _conf(value) -> str:
    """Formatea una confianza 0..1 como porcentaje."""
    try:
        return f"{round(float(value) * 100)}%"
    except (TypeError, ValueError):
        return "N/A"


def render_agentic_report(context: dict) -> str:
    """Genera el reporte final en Markdown del sistema multi-agente."""
    files = context["files"]
    conversation = context["conversation"]
    report = context["report"]
    agents = context["agents"]

    total_hallazgos = sum(len(f["audit"].get("hallazgos", [])) for f in files)
    total_validaciones = sum(len(f["val_data"].get("validaciones", [])) for f in files)
    total_confirmados = sum(
        1
        for f in files
        for v in f["val_data"].get("validaciones", [])
        if v.get("veredicto") == "CONFIRMADO"
    )
    total_fp = sum(
        1
        for f in files
        for v in f["val_data"].get("validaciones", [])
        if v.get("veredicto") == "FALSO_POSITIVO"
    )

    L: list[str] = [
        "# Reporte Final - Sistema Agentic de Guardrails (Grupo 3)",
        "",
        f"Modelo de los agentes: `{MODEL}` | Servidor MCP: `guardrails-auditor`",
        "",
        "## 1. Problema analizado",
        "",
        f"> {report.get('problema', 'Auditoria defensiva de codigo generado por IA.')}",
        "",
        f"{report.get('resumen_ejecutivo', '')}",
        "",
        "## 2. Agentes utilizados",
        "",
        "| Agente | Rol | Motor |",
        "|--------|-----|-------|",
    ]
    for a in agents:
        L.append(f"| {a['nombre']} | {a['rol']} | {a['motor']} |")

    L += [
        "",
        "## 3. Evidencia procesada",
        "",
        "| Archivo | Lenguaje | Lineas | SHA256 | Dependencias |",
        "|---------|----------|--------|--------|--------------|",
    ]
    for f in files:
        deps = ", ".join(f.get("declared", [])) or "-"
        L.append(
            f"| `{f['filename']}` | {f['language']} | {f['line_count']} | "
            f"`{f['sha256']}` | {deps} |"
        )

    L += [
        "",
        "## 4. Conversacion entre agentes (resumida)",
        "",
        "| # | De -> Para | Tarea | Evidencia | Resultado | Confianza | Siguiente accion |",
        "|---|-----------|-------|-----------|-----------|-----------|------------------|",
    ]
    for i, m in enumerate(conversation, 1):
        L.append(
            f"| {i} | {m['de']} -> {m['para']} | {m['tarea']} | {m['evidencia']} | "
            f"{m['resultado']} | {_conf(m['confianza'])} | {m['siguiente_accion']} |"
        )

    L += ["", "## 5. Hallazgos validados", ""]
    for f in files:
        L.append(f"### `{f['filename']}`")
        L.append("")
        validaciones = {
            v.get("referencia", ""): v for v in f["val_data"].get("validaciones", [])
        }
        hallazgos = f["audit"].get("hallazgos", [])
        if not hallazgos:
            L.append("_Sin hallazgos de seguridad._")
            L.append("")
        for h in hallazgos:
            titulo = h.get("titulo", "")
            v = validaciones.get(titulo, {})
            veredicto = VEREDICTO_ICON.get(v.get("veredicto", ""), "[?] sin veredicto")
            L += [
                f"- **[{h.get('severidad')}] {titulo}** (linea {h.get('linea')}, {h.get('cwe', 'N/A')})",
                f"  - Evidencia: `{h.get('evidencia')}`",
                f"  - Validador: {veredicto} ({_conf(v.get('confianza'))}) - {v.get('justificacion', 'sin justificacion')}",
                f"  - Reescritura segura: {h.get('reescritura_segura', '')}",
            ]
        riesgosas = [
            d
            for d in f["dep_data"].get("dependencias", [])
            if d.get("estado") in ("sospechoso", "desconocido")
        ]
        if riesgosas:
            L.append("  - Dependencias riesgosas:")
            for d in riesgosas:
                L.append(
                    f"    - `{d.get('paquete')}` ({d.get('estado')}): "
                    f"{d.get('riesgo', d.get('recomendacion', ''))}"
                )
        L.append("")

    L += [
        "## 6. Riesgos priorizados",
        "",
        "| Prioridad | Severidad | Riesgo | Archivo | Justificacion |",
        "|-----------|-----------|--------|---------|---------------|",
    ]
    for i, r in enumerate(report.get("riesgos_priorizados", []), 1):
        L.append(
            f"| {i} | {r.get('severidad')} | {r.get('titulo')} | "
            f"`{r.get('archivo', '-')}` | {r.get('justificacion', '')} |"
        )

    L += ["", "## 7. Recomendaciones", ""]
    for rec in report.get("recomendaciones", []):
        L.append(f"- {rec}")

    L += [
        "",
        "## 8. Validacion humana",
        "",
        "El sistema **recomienda**, el analista humano **valida**. Resumen del Agente Validador:",
        "",
        f"- Hallazgos de seguridad detectados: {total_hallazgos}",
        f"- Validaciones realizadas (seguridad + dependencias): {total_validaciones}",
        f"- Confirmados por el validador: {total_confirmados}",
        f"- Falsos positivos descartados: {total_fp}",
        "",
        "Puntos que requieren revision humana explicita:",
        "",
    ]
    human_points = []
    for f in files:
        for p in f["audit"].get("requiere_validacion_humana", []):
            human_points.append(f"- ({f['filename']}) {p}")
        for v in f["val_data"].get("validaciones", []):
            if v.get("veredicto") == "REVISION_HUMANA":
                human_points.append(
                    f"- ({f['filename']}) {v.get('referencia')}: {v.get('justificacion', '')}"
                )
    L += human_points or ["- (ninguno marcado automaticamente)"]

    L += ["", "## 9. Limitaciones del sistema", ""]
    limitaciones = report.get("limitaciones") or [
        "El analisis depende del criterio del LLM y puede variar entre ejecuciones.",
        "El catalogo de dependencias es local y no consulta los registros en vivo.",
        "No se ejecuta el codigo: el analisis es estatico y puede omitir fallos en runtime.",
    ]
    for lim in limitaciones:
        L.append(f"- {lim}")

    L += [
        "",
        "---",
        "",
        "*Sistema multi-agente sobre MCP real. La IA recomienda, el humano valida.*",
        "*PoC academica defensiva - Grupo 3 - Guardrails para Vibe Coding.*",
        "",
    ]
    return "\n".join(L)


def render_agentic_html(context: dict) -> str:
    """Version HTML autocontenida del reporte agentic (para la demo)."""
    files = context["files"]
    conversation = context["conversation"]
    report = context["report"]
    agents = context["agents"]

    css = """
    :root { color-scheme: light; }
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           background: #f8fafc; color: #0f172a; margin: 0; padding: 2rem; line-height: 1.55; }
    .wrap { max-width: 1040px; margin: 0 auto; }
    header { background: linear-gradient(135deg, #0f172a, #1e293b); color: white;
             padding: 2rem; border-radius: 14px; margin-bottom: 1.5rem; }
    header h1 { margin: 0 0 .4rem 0; font-size: 1.55rem; }
    header p { margin: 0; opacity: .85; }
    h2 { font-size: 1.2rem; margin-top: 2rem; border-bottom: 2px solid #e2e8f0; padding-bottom: .35rem; }
    table { width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: .86rem; }
    th, td { border: 1px solid #e2e8f0; padding: .5rem .6rem; text-align: left; vertical-align: top; }
    th { background: #f1f5f9; color: #334155; }
    code { background: #e2e8f0; padding: .1rem .35rem; border-radius: 4px; font-size: .82rem; }
    .card { background: white; padding: 1.25rem 1.5rem; border-radius: 12px;
            box-shadow: 0 1px 3px rgba(0,0,0,.06); margin-bottom: 1rem; }
    .ok { color: #16a34a; font-weight: 700; }
    .fp { color: #64748b; font-weight: 700; }
    .hum { color: #ca8a04; font-weight: 700; }
    .badge { color: white; padding: .12rem .5rem; border-radius: 999px; font-size: .72rem; font-weight: 700; }
    ul { margin: .3rem 0 .8rem 1.1rem; }
    footer { text-align: center; color: #94a3b8; font-size: .82rem; margin-top: 2rem; padding: 1rem; }
    """

    def chip(sev: str) -> str:
        return f'<span class="badge" style="background:{SEVERITY_COLORS.get(sev, "#475569")}">{_esc(sev)}</span>'

    P: list[str] = [
        "<!doctype html><html lang='es'><head><meta charset='utf-8'>",
        "<title>Reporte Agentic - Grupo 3</title>",
        f"<style>{css}</style></head><body><div class='wrap'>",
        "<header><h1>Sistema Agentic de Guardrails - Reporte Final</h1>",
        f"<p>Grupo 3 &middot; Modelo: <code>{_esc(MODEL)}</code> &middot; 5 agentes sobre MCP real</p></header>",
        "<div class='card'><h2 style='margin-top:0'>1. Problema analizado</h2>",
        f"<p>{_esc(report.get('problema', ''))}</p>",
        f"<p>{_esc(report.get('resumen_ejecutivo', ''))}</p></div>",
        "<div class='card'><h2 style='margin-top:0'>2. Agentes utilizados</h2>",
        "<table><tr><th>Agente</th><th>Rol</th><th>Motor</th></tr>",
    ]
    for a in agents:
        P.append(
            f"<tr><td>{_esc(a['nombre'])}</td><td>{_esc(a['rol'])}</td><td>{_esc(a['motor'])}</td></tr>"
        )
    P.append("</table></div>")

    P.append("<div class='card'><h2 style='margin-top:0'>3. Conversacion entre agentes</h2>")
    P.append(
        "<table><tr><th>#</th><th>De &rarr; Para</th><th>Tarea</th><th>Resultado</th>"
        "<th>Confianza</th><th>Siguiente accion</th></tr>"
    )
    for i, m in enumerate(conversation, 1):
        P.append(
            f"<tr><td>{i}</td><td>{_esc(m['de'])} &rarr; {_esc(m['para'])}</td>"
            f"<td>{_esc(m['tarea'])}</td><td>{_esc(m['resultado'])}</td>"
            f"<td>{_conf(m['confianza'])}</td><td>{_esc(m['siguiente_accion'])}</td></tr>"
        )
    P.append("</table></div>")

    P.append("<div class='card'><h2 style='margin-top:0'>4. Hallazgos validados</h2>")
    veredicto_class = {"CONFIRMADO": "ok", "FALSO_POSITIVO": "fp", "REVISION_HUMANA": "hum"}
    for f in files:
        P.append(f"<h3><code>{_esc(f['filename'])}</code></h3>")
        validaciones = {v.get("referencia", ""): v for v in f["val_data"].get("validaciones", [])}
        hallazgos = f["audit"].get("hallazgos", [])
        if not hallazgos:
            P.append("<p><em>Sin hallazgos de seguridad.</em></p>")
        P.append("<ul>")
        for h in hallazgos:
            v = validaciones.get(h.get("titulo", ""), {})
            cls = veredicto_class.get(v.get("veredicto", ""), "hum")
            P.append(
                f"<li>{chip(h.get('severidad', 'BAJA'))} <b>{_esc(h.get('titulo', ''))}</b> "
                f"(linea {_esc(h.get('linea', '?'))}, {_esc(h.get('cwe', 'N/A'))}) &mdash; "
                f"<span class='{cls}'>{_esc(v.get('veredicto', 'sin veredicto'))}</span> "
                f"({_conf(v.get('confianza'))})<br><small>{_esc(v.get('justificacion', ''))}</small></li>"
            )
        P.append("</ul>")
    P.append("</div>")

    P.append("<div class='card'><h2 style='margin-top:0'>5. Riesgos priorizados</h2>")
    P.append("<table><tr><th>#</th><th>Severidad</th><th>Riesgo</th><th>Archivo</th><th>Justificacion</th></tr>")
    for i, r in enumerate(report.get("riesgos_priorizados", []), 1):
        P.append(
            f"<tr><td>{i}</td><td>{chip(r.get('severidad', 'BAJA'))}</td>"
            f"<td>{_esc(r.get('titulo', ''))}</td><td><code>{_esc(r.get('archivo', '-'))}</code></td>"
            f"<td>{_esc(r.get('justificacion', ''))}</td></tr>"
        )
    P.append("</table></div>")

    P.append("<div class='card'><h2 style='margin-top:0'>6. Recomendaciones</h2><ul>")
    for rec in report.get("recomendaciones", []):
        P.append(f"<li>{_esc(rec)}</li>")
    P.append("</ul></div>")

    P.append("<div class='card'><h2 style='margin-top:0'>7. Limitaciones del sistema</h2><ul>")
    for lim in report.get("limitaciones", []):
        P.append(f"<li>{_esc(lim)}</li>")
    P.append("</ul></div>")

    P.append(
        "<footer>Sistema multi-agente sobre MCP real &middot; La IA recomienda, el humano valida"
        " &middot; Grupo 3</footer></div></body></html>"
    )
    return "".join(P)
