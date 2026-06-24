# Grupo 3 - Guardrails para Vibe Coding

## Tema asignado

**Guardrails para Vibe Coding**

El objetivo del grupo es construir una Prueba de Concepto (PoC) defensiva que funcione como auditor de codigo generado por IA. La solucion debe leer archivos de codigo vulnerables o sospechosos y pedirle a un LLM que identifique fallos de seguridad, dependencias falsas o malas practicas, proponiendo una reescritura segura.

## Objetivo general del proyecto

El paradigma de la ciberseguridad cambio: la IA ya no se usa solo como un chatbot generico, sino como un motor activo de defensa agentic para procesar datos, investigar alertas y asistir al analista.

El objetivo no es construir una infraestructura compleja ni conectar sistemas en vivo. El objetivo es construir una PoC mediante Vibe Coding. Se debe utilizar IA, por ejemplo ChatGPT, Claude, Gemini o Google AI Studio, para generar rapidamente una solucion que tome archivos estaticos, los procese usando un LLM y devuelva un analisis de seguridad accionable.

## Alcance del Grupo 3

### Insumo estatico requerido

2 o 3 archivos de codigo, por ejemplo Python o JavaScript, generados por IA que incluyan vulnerabilidades o librerias inventadas.

### Tarea de la IA

Crear un script que actue como auditor:

- Lee los archivos de codigo.
- Envia el contenido al LLM.
- Solicita la identificacion de fallos de seguridad.
- Detecta dependencias falsas o sospechosas.
- Pide recomendaciones de reescritura segura.

### Salida minima de la PoC

Un listado de **Hallazgos Criticos** que proponga la reescritura segura del codigo.

La salida puede ser:

- Terminal bien formateada.
- Archivo Markdown.
- HTML simple generado por el script.

## Reglas de la exposicion

- Tiempo estricto: 20 minutos de exposicion tecnica + 10 minutos de preguntas y debate.
- Presentacion minimalista: usar diapositivas solo para diagrama de flujo, ejemplos de datos y metricas.
- Evitar saturacion de texto.
- En los primeros 5 minutos se debe conectar el tema con el caso **Claude Mythos**.
- Debe explicarse en que se parece o diferencia la superficie de ataque y defensa del tema del grupo con el caso Claude Mythos.

## Entregables obligatorios

### 1. Uso de Vibe Coding

Explicar que herramientas de IA se usaron para programar la solucion y como se iteraron los prompts para que el codigo funcionara.

### 2. Procesamiento de datos

Demostrar en vivo como el script toma archivos estaticos de codigo y los procesa mediante IA.

### 3. Resultados visibles

Mostrar una salida estructurada del script. No se requiere un sistema web full-stack.

### 4. Validacion humana

La IA debe recomendar, pero el grupo debe explicar si el analisis fue correcto, si alucino o si omitio detalles importantes.

## Criterios de exclusion

- No configurar servidores, SIEMs, Suricata ni Zeek en vivo.
- No presentar un chatbot donde se escriba manualmente.
- No presentar herramientas ofensivas.
- El enfoque debe ser defensivo, tipo Blue Team.

## Dia de la exposicion

- Subir el documento de la exposicion a Turnitin antes de ingresar a clase.
- Preparar una presentacion corta para la clase.
- Hacer un demo corto del producto funcionando.

## Arquitectura de la PoC

MCP real + analisis 100% con LLM (API de OpenAI). El servidor MCP es el guardrail:
solo lee `samples/`, solo escribe en `output/` y nunca ejecuta el codigo auditado.

```text
src/client_demo.py (orquestador + LLM)
   |
   |  JSON-RPC sobre stdio
   v
src/server.py (servidor MCP "guardrails-auditor")
   +-- tool list_targets   -> descubre archivos en samples/
   +-- tool read_source    -> codigo con numeros de linea
   +-- tool write_report   -> persiste output/reporte.md
   |
src/auditor.py (prompt defensivo + render del reporte)
```

## Como ejecutar

### Opcion 1: Docker (recomendada para la demo)

```bash
cp .env.example .env   # completar OPENAI_API_KEY
docker compose up --build
open output/reporte.md
```

### Opcion 2: local con Python

```bash
pip install -r requirements.txt
export OPENAI_API_KEY="sk-..."
python src/client_demo.py
```

El modelo se configura con `OPENAI_MODEL` (default `gpt-5.1`).

## Parte II: Sistema Agentic (multi-agente sobre MCP)

La evolucion del proyecto convierte el auditor de un solo paso en un sistema de
**5 agentes de IA que conversan** sobre el mismo servidor MCP: Recoleccion,
Seguridad, Dependencias, Validador y Reporte. Cada agente intercambia mensajes
estructurados y el Validador actua como barrera anti-alucinacion.

```bash
export OPENAI_API_KEY="sk-..."
python src/orchestrator.py
```

Genera en `output/`:

- `reporte-agentic.md` y `reporte-agentic.html` (reporte final con 9 secciones).
- `conversacion-agentes.json` (intercambio completo entre agentes).

Detalle de la arquitectura, los agentes y el uso de vibe coding en
[docs/ARQUITECTURA-AGENTIC.md](docs/ARQUITECTURA-AGENTIC.md).

## Estructura del proyecto

```text
Grupo 3 - Guardrails para Vibe Coding/
  README.md            # este archivo
  PLAN.md              # plan y decisiones de arquitectura
  docs/
    ARQUITECTURA-AGENTIC.md  # arquitectura agentic + vibe coding (Parte II)
  samples/             # codigo vulnerable generado por IA (insumo estatico)
  src/
    server.py          # servidor MCP con los tools (guardrails)
    auditor.py         # prompt defensivo + LLM + render de reportes
    agents.py          # 5 agentes + protocolo de mensajes (Parte II)
    orchestrator.py    # cliente MCP que coordina a los agentes (Parte II)
    client_demo.py     # cliente MCP del flujo clasico de un solo paso
    webapp.py          # interfaz web drag & drop
  output/              # reportes generados
  presentacion/        # material de la exposicion
  Dockerfile
  docker-compose.yml
  requirements.txt
  .env.example
```
