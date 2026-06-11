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
