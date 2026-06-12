# Validación Humana — lo esencial

> "La IA recomienda; el humano valida si fue correcto, si alucinó o si omitió algo crítico."

Validé 2 archivos representativos del reporte contra el código real.

---

## `unsafe_file_processor.py` → el LLM acertó todo

Detectó las 5 vulnerabilidades reales sin inventar ninguna:
`eval` (CWE-94), `pickle.load` (CWE-502), `os.system` (CWE-78),
path traversal (CWE-22) e `import pysecureparse` muerto + dependencia inventada (CWE-561).

**Correcto. No alucinó. No omitió nada.**

---

## `vulnerable_login.py` → acertó, pero con 1 omisión crítica

Detectó bien lo grave: API key hardcodeada (CWE-798), MD5 sin sal (CWE-327) y
SQL injection x2 (CWE-89).

**Omisión crítica:** en el fix del SQLi propone `bcrypt.checkpw(...)`, asumiendo que las
contraseñas ya están en bcrypt. Pero el código original usa MD5. **No avisó que su fix del
SQLi y su fix del MD5 son interdependientes y exigen migrar los datos** — copiarlo tal cual
rompería el login.

**Correcto en lo grave, pero el humano debe conectar los dos fixes.**

---

## Conclusión

- **¿Fue correcto?** Sí, detectó el 100% de las vulnerabilidades reales.
- **¿Alucinó?** No inventó hallazgos falsos.
- **¿Omitió?** Sí: no enlazó el fix de SQLi con el de MD5, y la numeración de líneas tiene
  desfases de ±1 (la evidencia textual siempre fue exacta).
