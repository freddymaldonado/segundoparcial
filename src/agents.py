"""Agentes de IA y protocolo de mensajes del sistema agentic (Grupo 3).

Cada agente es un rol con una mision acotada. Los agentes NO ejecutan codigo:
razonan sobre la evidencia que les entrega el servidor MCP (los tools "miden",
los agentes "razonan") e intercambian mensajes estructurados a traves del bus
`Conversation`.

Roles:
- Agente de Recoleccion : lee codigo y dependencias via MCP (determinista).
- Agente de Seguridad   : detecta vulnerabilidades (LLM, reusa auditor.audit_file).
- Agente de Dependencias: evalua librerias riesgosas o inventadas (LLM + catalogo).
- Agente Validador      : confirma si cada hallazgo es real o falso positivo (LLM).
- Agente de Reporte     : prioriza riesgos y genera recomendaciones (LLM).
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from openai import OpenAI

from auditor import audit_file

MODEL = os.getenv("OPENAI_MODEL", "gpt-5.1")

AGENT_ROSTER = [
    {
        "nombre": "Agente de Recoleccion",
        "rol": "Lee el codigo generado por IA y sus dependencias via MCP.",
        "motor": "Determinista (tools MCP: list_targets, read_source, extraer_dependencias)",
    },
    {
        "nombre": "Agente de Seguridad",
        "rol": "Interpreta el codigo y genera hallazgos de vulnerabilidades.",
        "motor": "LLM",
    },
    {
        "nombre": "Agente de Dependencias",
        "rol": "Revisa librerias riesgosas o inventadas (slopsquatting).",
        "motor": "LLM + verificar_dependencias (catalogo determinista)",
    },
    {
        "nombre": "Agente Validador",
        "rol": "Confirma si cada hallazgo es real o un falso positivo.",
        "motor": "LLM",
    },
    {
        "nombre": "Agente de Reporte",
        "rol": "Prioriza riesgos y redacta recomendaciones accionables.",
        "motor": "LLM",
    },
]


@dataclass
class AgentMessage:
    """Mensaje estructurado que un agente envia a otro."""

    de: str
    para: str
    tarea: str
    evidencia: str
    resultado: str
    confianza: float
    siguiente_accion: str
    payload: dict = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def to_dict(self) -> dict:
        return asdict(self)


class Conversation:
    """Bus que registra el intercambio completo de mensajes entre agentes."""

    def __init__(self) -> None:
        self.messages: list[AgentMessage] = []

    def send(self, msg: AgentMessage) -> AgentMessage:
        self.messages.append(msg)
        return msg

    def to_list(self) -> list[dict]:
        return [m.to_dict() for m in self.messages]


def _ask_json(client: OpenAI, system: str, user: str) -> dict:
    """Llama al LLM forzando salida JSON y devuelve el objeto parseado."""
    response = client.chat.completions.create(
        model=MODEL,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    )
    return json.loads(response.choices[0].message.content)


# --------------------------------------------------------------------------- #
# Agente de Recoleccion (determinista: arma el mensaje desde la evidencia MCP) #
# --------------------------------------------------------------------------- #
def agente_recoleccion(source: dict, deps: dict, sha256: str) -> AgentMessage:
    """Construye el mensaje de evidencia recolectada via MCP."""
    declared = deps.get("declared", [])
    return AgentMessage(
        de="Agente de Recoleccion",
        para="Agente de Seguridad",
        tarea=f"Recolectar evidencia del archivo {source['filename']}",
        evidencia=f"sha256:{sha256} - {source['line_count']} lineas de {source['language']}",
        resultado=f"{source['line_count']} lineas leidas, {len(declared)} dependencias declaradas",
        confianza=1.0,
        siguiente_accion="Analizar vulnerabilidades y dependencias",
        payload={
            "filename": source["filename"],
            "language": source["language"],
            "line_count": source["line_count"],
            "dependencias_declaradas": declared,
        },
    )


# --------------------------------------------------------------------------- #
# Agente de Seguridad (reusa el auditor defensivo existente)                   #
# --------------------------------------------------------------------------- #
def agente_seguridad(client: OpenAI, source: dict) -> tuple[AgentMessage, dict]:
    """Detecta vulnerabilidades en el codigo y emite el mensaje correspondiente."""
    audit = audit_file(client, source["filename"], source["language"], source["numbered_code"])
    hallazgos = audit.get("hallazgos", [])
    confianza = 0.9 if hallazgos else 0.6
    msg = AgentMessage(
        de="Agente de Seguridad",
        para="Agente Validador",
        tarea=f"Analizar vulnerabilidades en {source['filename']}",
        evidencia=f"{source['line_count']} lineas de codigo {source['language']} (numeradas)",
        resultado=f"{len(hallazgos)} hallazgos de seguridad detectados",
        confianza=confianza,
        siguiente_accion="Validar cada hallazgo contra el codigo real",
        payload={
            "resumen": audit.get("resumen", ""),
            "hallazgos": hallazgos,
            "requiere_validacion_humana": audit.get("requiere_validacion_humana", []),
        },
    )
    return msg, audit


# --------------------------------------------------------------------------- #
# Agente de Dependencias                                                       #
# --------------------------------------------------------------------------- #
DEP_SYSTEM = """Eres el Agente de Dependencias de un sistema de auditoria defensiva.
Recibes las dependencias declaradas en un archivo y el veredicto DETERMINISTA de un
verificador (estandar / conocido / sospechoso / desconocido). Tu tarea:
1. Explicar el riesgo real de cada dependencia sospechosa o desconocida.
2. Detectar posibles librerias inventadas por un LLM (slopsquatting).
3. Recomendar una accion concreta (sustituir, verificar en el registro, eliminar).
NO inventes paquetes ni afirmes que existen sin evidencia. Respeta el veredicto
determinista como fuente de verdad sobre la existencia del paquete.

Responde SOLO con JSON valido:
{
  "dependencias": [
    {"paquete": "...", "ecosistema": "pypi|npm", "estado": "estandar|conocido|sospechoso|desconocido",
     "riesgo": "por que es riesgosa o segura", "recomendacion": "accion concreta", "confianza": 0.0}
  ],
  "resumen": "una frase",
  "confianza": 0.0
}"""


def agente_dependencias(
    client: OpenAI, deps: dict, verificadas: list[dict], source: dict
) -> tuple[AgentMessage, dict]:
    """Evalua las dependencias riesgosas o inventadas."""
    if not deps.get("declared"):
        data = {"dependencias": [], "resumen": "El archivo no declara dependencias externas.", "confianza": 1.0}
    else:
        user = json.dumps(
            {
                "archivo": source["filename"],
                "ecosistema": deps.get("ecosistema"),
                "declaradas": deps.get("declared", []),
                "verificacion_determinista": verificadas,
            },
            ensure_ascii=False,
        )
        data = _ask_json(client, DEP_SYSTEM, user)

    dep_findings = data.get("dependencias", [])
    riesgosas = [d for d in dep_findings if d.get("estado") in ("sospechoso", "desconocido")]
    msg = AgentMessage(
        de="Agente de Dependencias",
        para="Agente Validador",
        tarea=f"Evaluar dependencias de {source['filename']}",
        evidencia=f"{len(verificadas)} dependencias verificadas contra el catalogo",
        resultado=f"{len(riesgosas)} dependencias riesgosas o inventadas",
        confianza=float(data.get("confianza", 0.8)),
        siguiente_accion="Validar dependencias sospechosas",
        payload=data,
    )
    return msg, data


# --------------------------------------------------------------------------- #
# Agente Validador (anti-alucinacion)                                          #
# --------------------------------------------------------------------------- #
VAL_SYSTEM = """Eres el Agente Validador. Tu mision es EVITAR conclusiones inventadas.
Recibes el codigo real numerado y los hallazgos de los agentes de Seguridad y de
Dependencias. Para CADA hallazgo decide un veredicto comprobando la evidencia en el codigo:
- "CONFIRMADO": la evidencia existe claramente en la linea citada.
- "FALSO_POSITIVO": no hay evidencia en el codigo o el hallazgo es incorrecto.
- "REVISION_HUMANA": es ambiguo o depende de contexto externo no visible.
Cita siempre la linea o el fragmento que justifica tu veredicto.

Responde SOLO con JSON valido:
{
  "validaciones": [
    {"referencia": "titulo del hallazgo o paquete", "tipo": "seguridad|dependencia",
     "veredicto": "CONFIRMADO|FALSO_POSITIVO|REVISION_HUMANA",
     "justificacion": "por que, citando la linea", "confianza": 0.0}
  ],
  "resumen": "una frase",
  "confianza": 0.0
}"""


def agente_validador(
    client: OpenAI, audit: dict, dep_data: dict, source: dict
) -> tuple[AgentMessage, dict]:
    """Confirma o descarta cada hallazgo contra el codigo real."""
    user = json.dumps(
        {
            "archivo": source["filename"],
            "codigo_numerado": source["numbered_code"],
            "hallazgos_seguridad": audit.get("hallazgos", []),
            "hallazgos_dependencias": dep_data.get("dependencias", []),
        },
        ensure_ascii=False,
    )
    data = _ask_json(client, VAL_SYSTEM, user)

    validaciones = data.get("validaciones", [])
    confirmados = [v for v in validaciones if v.get("veredicto") == "CONFIRMADO"]
    falsos = [v for v in validaciones if v.get("veredicto") == "FALSO_POSITIVO"]
    msg = AgentMessage(
        de="Agente Validador",
        para="Agente de Reporte",
        tarea=f"Validar hallazgos de {source['filename']}",
        evidencia=f"{len(validaciones)} hallazgos revisados contra el codigo",
        resultado=f"{len(confirmados)} confirmados, {len(falsos)} falsos positivos",
        confianza=float(data.get("confianza", 0.8)),
        siguiente_accion="Consolidar el reporte final priorizado",
        payload=data,
    )
    return msg, data


# --------------------------------------------------------------------------- #
# Agente de Reporte                                                           #
# --------------------------------------------------------------------------- #
REP_SYSTEM = """Eres el Agente de Reporte de un sistema agentic defensivo (Blue Team).
Recibes los hallazgos YA validados de varios archivos. Tu tarea:
1. Resumir el problema analizado.
2. Priorizar los riesgos confirmados (los CONFIRMADOS pesan mas que los de revision humana).
3. Dar recomendaciones accionables y defensivas (nunca como explotar).
4. Declarar honestamente las limitaciones del sistema.

Responde SOLO con JSON valido:
{
  "problema": "que se analizo, en una o dos frases",
  "resumen_ejecutivo": "estado general de seguridad",
  "riesgos_priorizados": [
    {"titulo": "...", "severidad": "CRITICA|ALTA|MEDIA|BAJA", "archivo": "...", "justificacion": "..."}
  ],
  "recomendaciones": ["..."],
  "limitaciones": ["..."],
  "confianza": 0.0
}"""


def agente_reporte(client: OpenAI, resumen_archivos: list[dict]) -> tuple[AgentMessage, dict]:
    """Consolida los hallazgos validados en un reporte priorizado."""
    user = json.dumps({"archivos": resumen_archivos}, ensure_ascii=False)
    data = _ask_json(client, REP_SYSTEM, user)
    msg = AgentMessage(
        de="Agente de Reporte",
        para="Analista humano",
        tarea="Generar el reporte final priorizado",
        evidencia=f"{len(resumen_archivos)} archivos auditados y validados",
        resultado=f"{len(data.get('riesgos_priorizados', []))} riesgos priorizados",
        confianza=float(data.get("confianza", 0.85)),
        siguiente_accion="Validacion humana del analista antes de actuar",
        payload=data,
    )
    return msg, data


def resumen_para_reporte(files: list[dict]) -> list[dict]:
    """Compacta cada archivo para el Agente de Reporte (solo lo confirmado)."""
    resumen = []
    for f in files:
        validaciones = f["val_data"].get("validaciones", [])
        confirmados = [v for v in validaciones if v.get("veredicto") == "CONFIRMADO"]
        riesgosas = [
            d
            for d in f["dep_data"].get("dependencias", [])
            if d.get("estado") in ("sospechoso", "desconocido")
        ]
        resumen.append(
            {
                "archivo": f["filename"],
                "lenguaje": f["language"],
                "hallazgos_seguridad": [
                    {
                        "titulo": h.get("titulo"),
                        "severidad": h.get("severidad"),
                        "linea": h.get("linea"),
                        "cwe": h.get("cwe"),
                    }
                    for h in f["audit"].get("hallazgos", [])
                ],
                "validaciones_confirmadas": [
                    {"referencia": v.get("referencia"), "confianza": v.get("confianza")}
                    for v in confirmados
                ],
                "dependencias_riesgosas": riesgosas,
            }
        )
    return resumen


# --------------------------------------------------------------------------- #
# Back-and-forth: el Validador debate los hallazgos dudosos con su autor       #
# (deterministico, citando la evidencia ya producida; no consume mas LLM)      #
# --------------------------------------------------------------------------- #
def _autor_de(validacion: dict) -> str:
    """Agente que origino el hallazgo segun su tipo."""
    return (
        "Agente de Dependencias"
        if validacion.get("tipo") == "dependencia"
        else "Agente de Seguridad"
    )


def validador_cuestiona(validacion: dict, archivo: str) -> AgentMessage:
    """El Validador devuelve un hallazgo dudoso a su autor pidiendo respaldo."""
    autor = _autor_de(validacion)
    ref = validacion.get("referencia", "hallazgo")
    veredicto = validacion.get("veredicto", "REVISION_HUMANA")
    motivo = validacion.get("justificacion", "la evidencia en el codigo no es concluyente")
    return AgentMessage(
        de="Agente Validador",
        para=autor,
        tarea=f"Cuestionar el hallazgo '{ref}' en {archivo}",
        evidencia=f"Veredicto preliminar: {veredicto}. {motivo}",
        resultado=f"Se solicita a {autor.replace('Agente de ', '').replace('Agente ', '')} que confirme o reformule el hallazgo",
        confianza=float(validacion.get("confianza", 0.6)),
        siguiente_accion=f"Esperar la replica de {autor}",
        payload={"referencia": ref, "veredicto_preliminar": veredicto, "tipo": "cuestionamiento"},
    )


def agente_responde(validacion: dict, audit: dict, dep_data: dict, archivo: str) -> AgentMessage:
    """El autor del hallazgo replica al Validador con la evidencia que respalda su postura."""
    autor = _autor_de(validacion)
    ref = validacion.get("referencia", "hallazgo")
    veredicto = validacion.get("veredicto", "REVISION_HUMANA")

    # Recupera la evidencia original que produjo el autor.
    evidencia_original = ""
    if autor == "Agente de Seguridad":
        for h in audit.get("hallazgos", []):
            if h.get("titulo") == ref:
                evidencia_original = f"linea {h.get('linea', '?')}: {h.get('evidencia', '')}".strip()
                break
    else:
        for d in dep_data.get("dependencias", []):
            if d.get("paquete") == ref:
                evidencia_original = f"paquete '{d.get('paquete')}' clasificado como {d.get('estado')}: {d.get('riesgo', '')}".strip()
                break

    if veredicto == "FALSO_POSITIVO":
        resultado = f"Acepto el veredicto: retiro '{ref}' como falso positivo"
        siguiente = "El Validador descarta el hallazgo del reporte final"
        postura = "El Validador tiene razon; el codigo no respalda el riesgo reportado."
    else:  # REVISION_HUMANA u otro
        resultado = f"Mantengo '{ref}' pero coincido en derivarlo a revision humana"
        siguiente = "El Validador escala el hallazgo a validacion humana"
        postura = "La evidencia en el codigo es real, pero su criticidad depende de contexto externo."

    return AgentMessage(
        de=autor,
        para="Agente Validador",
        tarea=f"Responder al cuestionamiento sobre '{ref}' en {archivo}",
        evidencia=evidencia_original or "evidencia del analisis previo",
        resultado=resultado,
        confianza=float(validacion.get("confianza", 0.6)),
        siguiente_accion=siguiente,
        payload={"referencia": ref, "postura": postura, "tipo": "replica"},
    )

