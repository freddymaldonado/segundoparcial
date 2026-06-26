# Parte II — Proyecto Agentic con MCP
### Grupo 3 · Guardrails para Vibe Coding

> 7 slides · ~8 min · cierra con **demo en vivo**
> Separador de slide: `---` · Los `[[ ... ]]` son marcadores de screenshot/diagrama para mostrar en vivo.

---

## Slide 1 — El problema

# Guardrails para Vibe Coding
### Cuando la IA escribe el código, ¿quién lo audita?

- El *vibe coding* genera código rápido… y también **vulnerabilidades, secretos y dependencias inventadas (slopsquatting)**.
- En la Parte I construimos un **auditor de código**. Hoy lo convertimos en un **sistema agentic**.
- **Idea central:** varios agentes de IA **conversan, se asignan tareas, validan evidencia y generan un reporte** — siempre con un humano que valida.

> **La IA recomienda, el humano valida.**

`[[ Logo / portada del proyecto en pantalla ]]`

---

## Slide 2 — Arquitectura MCP

# Una arquitectura real sobre MCP

- **Cliente MCP** → la webapp orquestadora (FastAPI + streaming en vivo).
- **Servidor MCP** `guardrails-auditor` → expone las herramientas por *stdio*.
- **Agentes de IA** (gpt-5.1) → consumen las herramientas y conversan entre sí.
- **Evidencia** → el código generado por IA que se sube a analizar.
- **Reporte final** → Markdown + **HTML** persistidos vía MCP.

> **Guardrail clave del servidor:** solo **lee muestras** y **escribe reportes**. **Nunca ejecuta el código** que audita.

`[[ Diagrama de arquitectura: Cliente → Servidor MCP → Tools / Agentes / Evidencia → Reporte ]]`

---

## Slide 3 — Los agentes

# 5 agentes, 5 roles

| Agente | Rol |
|---|---|
| 📥 **Recolección** | Lee el código, extrae y verifica dependencias |
| 🛡️ **Seguridad** | Busca vulnerabilidades (OWASP, secretos, patrones peligrosos) |
| 📦 **Dependencias** | Detecta librerías riesgosas / inventadas (*slopsquatting*) |
| ✅ **Validador** | Confirma si cada hallazgo es **real o falso positivo** |
| 📝 **Reporte** | Prioriza riesgos y redacta el reporte para el 👤 **analista humano** |

- **Seguridad y Dependencias corren en paralelo** (`asyncio`) → más rápido y realista.
- Cubrimos los 4 roles mínimos exigidos **+1**.

`[[ Pipeline de agentes en vivo cambiando de estado ]]`

---

## Slide 4 — Comunicación real entre agentes

# No es un chatbot: es un protocolo

Cada mensaje estructurado lleva los **7 campos** exigidos:

`Emisor → Receptor · Tarea · Evidencia · Resultado · Confianza · Siguiente acción`

### Y hay back-and-forth real ↔
- El **Validador cuestiona** un hallazgo dudoso y lo devuelve a su autor.
- El **autor replica con su evidencia**: lo retira (falso positivo) o lo mantiene y lo **escala a revisión humana**.
- Todo el intercambio se ve **en vivo y se guarda** (`registrar_conversacion`).

`[[ Feed de conversación mostrando un cuestionamiento + réplica (etiqueta ↔ debate) ]]`

---

## Slide 5 — Herramientas MCP funcionales

# Tools del servidor MCP

| Herramienta | Qué hace |
|---|---|
| `list_targets()` | Lista los archivos auditables |
| `read_source()` | Lee el código (sin ejecutarlo) |
| `extraer_dependencias()` | Detecta librerías declaradas |
| `verificar_dependencias()` | Clasifica: estándar / conocida / **sospechosa** |
| `write_report()` / `write_html()` | Persisten el reporte final |
| `registrar_conversacion()` | Guarda el diálogo entre agentes |

> **Seguridad agregada a mano:** `_safe_resolve` evita *path traversal*; el servidor **no tiene** ninguna tool que ejecute código.

`[[ Consola de logs MCP mostrando las llamadas a las tools en tiempo real ]]`

---

## Slide 6 — Vibe Coding (cómo usamos IA)

# Construido con IA, asegurado por nosotros

- **Prompts principales:** "convertir el auditor en multi-agente sobre MCP", "protocolo de mensajes de 7 campos", "back-and-forth entre Validador y autor".
- **Errores que encontró la IA y corregimos:**
  - Riesgo de *path traversal* en el servidor → añadimos `_safe_resolve`.
  - La IA tendía a **inventar paquetes** → forzamos veredicto **determinista** de dependencias.
- **Decisiones de seguridad manuales:**
  - El servidor **nunca ejecuta** el código auditado.
  - **Validación humana obligatoria** antes del reporte final.

`[[ Captura de un prompt + corrección hecha por el grupo ]]`

---

## Slide 7 — Demo + reporte final

# Demo en vivo 🎬

En la webapp veremos, en tiempo real:
1. El **servidor MCP** levantando y publicando sus tools.
2. Los **5 agentes** trabajando (Seguridad + Dependencias en paralelo).
3. El **back-and-forth** entre agentes ↔.
4. El **reporte final HTML** abriéndose en pestaña nueva.

### El reporte incluye todo lo pedido
Problema · Agentes · Evidencia procesada · Conversación · Hallazgos · **Riesgos priorizados** · Recomendaciones · **Validación humana** · **Limitaciones**

> **Limitación honesta:** la IA prioriza y explica, pero **el humano decide**. El sistema asiste, no reemplaza.

`[[ Demo en vivo + reporte HTML final en pantalla ]]`
