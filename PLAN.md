# PLAN.md - Grupo 3: Guardrails para Vibe Coding

Estado: revision 3 - APROBADO E IMPLEMENTADO.

Decisiones finales: MCP real + analisis 100% con LLM (API de OpenAI, sin Semgrep ni motor estatico) + Docker. Tools reducidos a 4 para mantener la PoC simple: `list_targets`, `read_source`, `write_report` en el servidor MCP, y el analisis lo hace el LLM directamente. La seccion 6 conserva el diseno extendido como referencia historica del debate.

## 1. Objetivo de la PoC

Construir una prueba de concepto defensiva que audite codigo generado por IA.

La PoC debe:

- Tomar 2 o 3 archivos estaticos de codigo vulnerable o sospechoso.
- Leer esos archivos automaticamente desde una carpeta local.
- Enviar el contenido a un LLM mediante un script.
- Pedir al LLM que detecte fallos de seguridad, malas practicas y dependencias falsas.
- Generar una salida visible con hallazgos criticos y propuesta de reescritura segura.
- Permitir validacion humana: explicar que acerto el LLM, que omitio y donde podria haber alucinado.

## 2. Tema asignado

Linea de investigacion: Guardrails para Vibe Coding.

Insumo estatico requerido:

- 2 o 3 archivos Python o JavaScript generados por IA.
- Los archivos deben incluir vulnerabilidades o librerias inventadas.

Tarea de la IA:

- Actuar como auditor defensivo.
- Identificar vulnerabilidades.
- Detectar dependencias falsas o sospechosas.
- Proponer una reescritura segura.

Salida minima:

- Listado de Hallazgos Criticos.
- Recomendaciones de reescritura segura.

## 3. Idea central para la exposicion

Mensaje principal:

> Vibe Coding acelera el desarrollo, pero tambien puede introducir codigo inseguro, dependencias inexistentes y patrones peligrosos. La defensa agentic aparece como una capa de revision automatizada que ayuda al analista humano a detectar riesgos antes de ejecutar o desplegar ese codigo.

La PoC no intenta reemplazar al analista. La IA recomienda, el humano valida.

## 4. Conexion obligatoria con Claude Mythos

Debe aparecer en los primeros 5 minutos.

Contexto del caso:

- Claude Mythos es el nuevo modelo de Anthropic.
- Es tan potente que Anthropic no lo libera al publico general en su lanzamiento.
- Solo se entrega a grandes empresas, con acceso controlado, para que parchen su propio software.
- La razon: la misma capacidad que encuentra y corrige vulnerabilidades a escala sirve para encontrarlas y explotarlas. Liberarlo abierto seria peligroso.

Paralelo propuesto con nuestro tema:

- Mythos demuestra el doble uso: un modelo capaz de parchar software tambien es capaz de atacarlo. La frontera entre defensa y ofensa no es la capacidad, es el guardrail.
- Anthropic aplica guardrails de distribucion: acceso restringido, clientes verificados, uso supervisado. Nosotros aplicamos guardrails de uso: el LLM solo audita, nunca ejecuta, y el humano valida.
- Mythos se usa para revisar y parchar codigo existente. Nuestra PoC hace exactamente eso a escala de aula: auditar codigo generado por IA y proponer la reescritura segura antes de usarlo.
- Leccion comun: IA potente en seguridad solo es aceptable dentro de un perimetro controlado con supervision humana.

Diferencia clave:

- Mythos es el motor: modelo frontera protegido por escasez de acceso.
- Nuestro proyecto es la arquitectura de control alrededor del motor: servidor MCP con tools acotados, permisos minimos y validacion humana. Protegemos por diseno, no por escasez.

## 5. Arquitectura elegida: MCP real local

Decision del grupo: MCP real (antigua Opcion C). Las opciones de script simple e inspirada en MCP quedan descartadas como entrega final; el script simple sobrevive solo como plan B de demo (ver seccion 16).

### Vision general

```text
Host MCP con LLM (Claude Desktop / VS Code / cliente propio en Python)
   |
   |  JSON-RPC sobre stdio
   v
Servidor MCP "guardrails-auditor" (Python, SDK oficial mcp / FastMCP)
   |
   +--> Tools de inventario:  list_targets, read_source
   +--> Tools de analisis:    scan_code, extract_dependencies,
   |                          verify_dependencies, secret_scan
   +--> Tools de sintesis:    llm_audit_packet, write_report
   |
   +--> Resource: samples://<archivo>  (codigo bajo auditoria, solo lectura)
   +--> Prompt:   auditor_defensivo    (prompt parametrizado del servidor)
   |
   v
output/reporte.md (+ output/reporte.html opcional)
```

### Principios de diseno (estos son los guardrails)

1. El servidor nunca ejecuta el codigo auditado. Solo lo lee y lo analiza estaticamente.
2. Cada tool hace una sola cosa y declara input/output con schema.
3. Acceso a archivos confinado: lectura solo en `samples/`, escritura solo en `output/`, sin path traversal.
4. El LLM razona; los tools miden. Los hallazgos del LLM se contrastan con la evidencia estatica de los tools.
5. Salidas estructuradas en JSON para poder auditar al auditor.

### Stack tecnico

- Python 3.11+ con el SDK oficial `mcp` (FastMCP) sobre stdio. Ya hay experiencia previa en el workspace (carpeta MCPL) con servidores MCP en Python.
- Motor de analisis estatico: Semgrep como inspiracion del diseno y, si se instala, como backend real de `scan_code` (`pip install semgrep`). Verificado: hoy NO esta instalado en esta maquina.
- Fallback sin Semgrep: mini-motor propio de reglas (modulo `ast` para Python, regex para JS) con el mismo formato de salida que Semgrep: rule_id, severity, line, snippet, message.
- Host para la demo: Claude Desktop o VS Code como host MCP; plan B, cliente Python propio que orquesta los tools y llama a la API del LLM.

## 6. Diseno detallado de los tools (inspirado en Semgrep)

Referencia: el servidor MCP oficial de Semgrep expone tools como `semgrep_scan`, `security_check` y `get_abstract_syntax_tree`. Tomamos ese diseno como inspiracion, adaptado a nuestra PoC defensiva.

### Tabla resumen

| # | Tool | Tipo | Que hace | Backend |
|---|------|------|----------|---------|
| 1 | `list_targets` | inventario | Lista archivos auditables en `samples/` con lenguaje y hash | os + heuristica de extension |
| 2 | `read_source` | inventario | Devuelve codigo con numeros de linea y metadatos | lectura confinada |
| 3 | `scan_code` | analisis | Escaneo de patrones inseguros con reglas tipo Semgrep | Semgrep o mini-motor propio |
| 4 | `extract_dependencies` | analisis | Extrae imports/requires declarados | `ast` (Python) + regex (JS) |
| 5 | `verify_dependencies` | analisis | Marca dependencias inexistentes o sospechosas (slopsquatting) | catalogo local + consulta opcional a PyPI/npm |
| 6 | `secret_scan` | analisis | Detecta secretos hardcodeados | regex de alta precision |
| 7 | `llm_audit_packet` | sintesis | Arma el paquete de evidencia (codigo + hallazgos estaticos) para el LLM | composicion JSON |
| 8 | `write_report` | sintesis | Persiste el reporte final en `output/` | escritura confinada |

### Especificacion por tool

#### 1. list_targets

- Input: `{ "dir": "samples" }` (opcional, default `samples/`).
- Output: `[ { "path", "language", "size_bytes", "sha256" } ]`.
- Guardrail: solo lista dentro de la raiz del proyecto; allowlist de extensiones (.py, .js).

#### 2. read_source

- Input: `{ "path": "samples/vulnerable_login.py" }`.
- Output: `{ "path", "language", "numbered_code", "line_count" }`.
- Guardrail: rechaza rutas fuera de `samples/` (normalizacion + chequeo de prefijo). Limite de tamano, por ejemplo 100 KB.

#### 3. scan_code (corazon del proyecto, inspirado en semgrep_scan)

- Input: `{ "path": "...", "ruleset": "default" }`.
- Output: findings en formato Semgrep simplificado:
  `{ "rule_id", "severity": "CRITICAL|HIGH|MEDIUM|LOW", "line", "snippet", "message", "cwe" }`.
- Backend A (preferido): Semgrep real con `--config p/security-audit --json`, normalizando la salida.
- Backend B (fallback offline): mini-motor propio con reglas como:
  - `py.eval-exec`: eval/exec sobre entrada externa (CWE-95).
  - `py.sql-concat`: SQL armado con f-string o concatenacion (CWE-89).
  - `py.subprocess-shell`: subprocess con shell=True (CWE-78).
  - `py.pickle-load`: deserializacion insegura (CWE-502).
  - `py.weak-hash`: md5/sha1 para passwords (CWE-327/916).
  - `js.eval`: eval/Function sobre datos externos (CWE-95).
  - `js.child-process-exec`: exec con input externo (CWE-78).
- Guardrail: el tool reporta; no corrige ni ejecuta nada.

#### 4. extract_dependencies

- Input: `{ "path": "..." }`.
- Output: `{ "declared": [...], "stdlib": [...], "third_party": [...] }`.
- Backend: modulo `ast` para Python (Import/ImportFrom); regex de require/import para JS.

#### 5. verify_dependencies (el tool estrella contra librerias inventadas)

- Input: `{ "packages": ["quantumsec_ai"], "ecosystem": "pypi|npm" }`.
- Output: `[ { "package", "status": "exists|not_found|suspicious", "evidence" } ]`.
- Dos modos:
  - Online: GET a `https://pypi.org/pypi/<pkg>/json` y `https://registry.npmjs.org/<pkg>`, timeout corto, solo lectura.
  - Offline (demo segura): catalogo local de paquetes reales conocidos + lista de los inventados en nuestras muestras.
- Demuestra la defensa contra slopsquatting y alucinacion de dependencias: el riesgo numero uno del vibe coding.

#### 6. secret_scan

- Input: `{ "path": "..." }`.
- Output: findings `{ "type": "api_key|password|token", "line", "masked_match" }`.
- Guardrail: el secreto se enmascara (solo prefijo visible); nunca se imprime completo.

#### 7. llm_audit_packet

- Input: `{ "path": "..." }`.
- Output: JSON unico con codigo numerado + findings de los tools 3 a 6, listo para pasarse al LLM junto al prompt `auditor_defensivo`.
- Nota: con un host real (Claude Desktop) el LLM llama los tools 1 a 6 directamente y este tool es opcional; con cliente propio es el punto de integracion con la API.

#### 8. write_report

- Input: `{ "markdown": "...", "filename": "reporte.md" }`.
- Output: `{ "path": "output/reporte.md", "bytes_written" }`.
- Guardrail: solo escribe dentro de `output/`; rechaza cualquier otra ruta.

### Prompt y resources del servidor

- Prompt MCP `auditor_defensivo`: registrado en el servidor y parametrizado (archivo, hallazgos), para que cualquier host use siempre el mismo marco defensivo.
- Resource `samples://<archivo>`: expone el codigo bajo auditoria como recurso de solo lectura.

### Flujo agentic en la demo

1. El host (LLM) llama `list_targets`.
2. Por cada archivo: `read_source` -> `scan_code` -> `extract_dependencies` -> `verify_dependencies` -> `secret_scan`.
3. El LLM cruza la evidencia: confirma, descarta o agrega hallazgos y redacta la reescritura segura.
4. El LLM llama `write_report` con el reporte final.
5. El humano valida con la matriz de la seccion 12.

## 7. Flujo funcional de la PoC

1. Se levanta el servidor MCP `guardrails-auditor` (stdio).
2. El host conecta, descubre los tools y el LLM recibe el prompt `auditor_defensivo`.
3. El LLM llama `list_targets` y descubre los archivos de `samples/`.
4. Por cada archivo, el LLM encadena tools:
   - `read_source` para ver el codigo numerado.
   - `scan_code` para hallazgos de patrones inseguros.
   - `extract_dependencies` + `verify_dependencies` para dependencias falsas.
   - `secret_scan` para credenciales hardcodeadas.
5. El LLM cruza la evidencia estatica con su analisis semantico: confirma, descarta o agrega hallazgos y redacta la reescritura segura.
6. El LLM llama `write_report` y se genera `output/reporte.md`.
7. El grupo revisa el reporte y completa la matriz de validacion humana.

## 8. Hallazgos esperados

Ejemplos de hallazgos que queremos que aparezcan:

- Dependencia inventada o no verificable.
- Uso inseguro de `eval` o ejecucion dinamica.
- SQL injection por concatenacion de strings.
- Secretos hardcodeados.
- Falta de validacion de entrada.
- Deserializacion insegura.
- Uso inseguro de comandos del sistema.
- Manejo debil de autenticacion.
- Ausencia de control de errores seguro.
- Recomendacion de reescritura con parametros, validacion y librerias reales.

## 9. Archivos de ejemplo propuestos

Crear 3 muestras en `samples/`:

```text
samples/
  vulnerable_login.py
  fake_ai_dependency.js
  unsafe_file_processor.py
```

Contenido esperado:

- `vulnerable_login.py`: simula login con SQL injection, secreto hardcodeado y hashing debil.
- `fake_ai_dependency.js`: usa una libreria inventada y procesa entrada de forma insegura.
- `unsafe_file_processor.py`: usa `eval`, rutas no validadas o comandos del sistema inseguros.

Nota:

- Las muestras deben ser claramente defensivas y no deben convertirse en herramienta ofensiva.
- Deben existir solo para auditoria y demostracion.

## 10. Prompt del auditor

Crear un prompt base con estas reglas:

- Actua como auditor defensivo de codigo generado por IA.
- No expliques como explotar vulnerabilidades paso a paso.
- Clasifica hallazgos por severidad: Critica, Alta, Media, Baja.
- Detecta dependencias falsas o sospechosas.
- Propone reescritura segura.
- Distingue evidencia observada de inferencia.
- Marca posibles alucinaciones o puntos que requieren validacion humana.
- Devuelve salida estructurada en Markdown o JSON.

## 11. Salida del reporte

Formato recomendado: Markdown.

Estructura:

```text
# Reporte de Auditoria IA - Grupo 3

## Resumen ejecutivo

## Metricas
- Archivos analizados
- Hallazgos criticos
- Dependencias sospechosas
- Recomendaciones de reescritura

## Hallazgos Criticos

## Hallazgos Altos y Medios

## Dependencias falsas o sospechosas

## Reescritura segura propuesta

## Validacion humana

## Limitaciones del analisis
```

## 12. Validacion humana

Para cada hallazgo importante, agregar una mini matriz:

```text
Hallazgo | Evidencia en codigo | Veredicto humano | Comentario
```

Veredictos posibles:

- Correcto.
- Parcialmente correcto.
- Dudoso.
- Alucinacion.
- Omitido por el LLM.

Esto es clave porque la consigna pide explicar si el LLM acerto, alucino u omitio detalles.

## 13. Plan de demo en vivo

Demo ideal: 3 a 5 minutos.

Pasos:

1. Mostrar rapidamente `samples/`.
2. Mostrar el servidor MCP conectado al host, con la lista de tools visible.
3. Pedir la auditoria y dejar que el LLM encadene los tools en vivo.
4. Mostrar que se genera `output/reporte.md` y abrirlo.
5. Explicar 2 hallazgos criticos: 1 de `scan_code` y 1 dependencia inventada de `verify_dependencies`.
6. Mostrar 1 caso donde el humano valida o corrige al LLM.

Comandos esperados:

```bash
# desarrollo: probar tools con MCP Inspector
mcp dev src/server.py

# demo plan A: host MCP (Claude Desktop / VS Code) conectado al servidor

# demo plan B: cliente propio
python src/client_demo.py --samples samples --output output/reporte.md
```

Si se usa proveedor LLM real, usar variable de entorno:

```bash
export ANTHROPIC_API_KEY="..."
```

No guardar claves dentro del codigo.

## 14. Presentacion minimalista

Propuesta de diapositivas:

1. Titulo: Guardrails para Vibe Coding.
2. Conexion con Claude Mythos.
3. Problema: codigo generado por IA puede traer riesgos.
4. Diagrama de flujo de la PoC.
5. Ejemplo de archivo vulnerable.
6. Ejemplo de hallazgo generado.
7. Validacion humana.
8. Demo.
9. Conclusiones.

Regla:

- Poco texto.
- Usar diagramas, capturas y metricas.

## 15. Herramientas de IA a declarar

Durante la exposicion debemos decir que usamos Vibe Coding.

Ejemplos a documentar:

- GitHub Copilot para generar estructura y codigo inicial.
- ChatGPT, Claude, Gemini o Google AI Studio para iterar prompts de auditoria.
- Revision humana para ajustar falsos positivos y salidas.

Crear luego un archivo opcional:

```text
VIBE_CODING_LOG.md
```

Contenido:

- Prompt usado.
- Que genero la IA.
- Que fallo.
- Como se corrigio.

## 16. Riesgos del proyecto

Riesgo: el LLM no responde en vivo.
Mitigacion: guardar una salida ejemplo en `output/reporte_demo.md`.

Riesgo: el LLM alucina dependencias falsas.
Mitigacion: separar dependencias detectadas localmente de inferencias del LLM.

Riesgo: demo demasiado larga.
Mitigacion: analizar solo 2 o 3 archivos pequenos.

Riesgo: parecer herramienta ofensiva.
Mitigacion: enfocar todo en auditoria, reescritura segura y defensa.

Riesgo: el servidor MCP falle en vivo (host no conecta, stdio roto).
Mitigacion: cliente propio `src/client_demo.py` como plan B con los mismos tools, y reporte pregrabado `output/reporte_demo.md` como plan C.

Riesgo: Semgrep no instalado o lento en la maquina de la demo.
Mitigacion: mini-motor fallback con el mismo formato de salida; el backend definitivo se decide en el ensayo.

## 17. Decisiones para debatir antes de implementar

Resueltas:

1. Arquitectura: MCP real. RESUELTO.
2. Lenguaje: Python con SDK oficial `mcp` (FastMCP). RESUELTO.
3. Backend de analisis: 100% LLM via API de OpenAI (modelo configurable por env `OPENAI_MODEL`). Sin Semgrep. RESUELTO.
4. Tools finales: `list_targets`, `read_source`, `write_report` + analisis LLM en el cliente. RESUELTO.
5. Empaquetado: Docker + docker-compose. RESUELTO.
6. Salida: Markdown en `output/reporte.md`. RESUELTO.
7. Archivos vulnerables: los 3 de la seccion 9. RESUELTO.

## 18. Propuesta de implementacion si se aprueba este plan

Fase 1: Insumos y reglas

- Crear `samples/` con 3 archivos vulnerables (seccion 9).
- Definir reglas del mini-motor y, si se aprueba, instalar Semgrep en el venv.
- Crear `prompts/auditor_defensivo.md`.

Fase 2: Servidor MCP

- `src/server.py`: servidor FastMCP con los 8 tools de la seccion 6.
- `src/scanners.py`: backend de `scan_code` (Semgrep + fallback propio).
- `src/deps.py`: extract/verify dependencies (modo online y offline).
- `src/report.py`: generacion de Markdown (y HTML opcional).
- Probar tools con MCP Inspector: `mcp dev src/server.py`.

Fase 3: Cliente y demo

- Conectar a un host (Claude Desktop / VS Code) o crear `src/client_demo.py` propio.
- Generar `output/reporte.md` real y `output/reporte_demo.md` pregrabado.
- Crear `VIBE_CODING_LOG.md`.

Fase 4: Exposicion

- Diagrama de flujo del servidor y tools para las diapositivas.
- Matriz de validacion humana con los hallazgos reales.
- Ensayo de demo con cronometro.

## 19. Criterio de exito

La PoC se considera lista si:

- Procesa automaticamente archivos estaticos.
- Usa un LLM para generar analisis de seguridad.
- Produce hallazgos criticos visibles.
- Propone reescritura segura.
- Permite explicar claramente Vibe Coding y validacion humana.
- Tiene una demo corta y repetible.
- Conecta con Claude Mythos en los primeros 5 minutos de la exposicion.
