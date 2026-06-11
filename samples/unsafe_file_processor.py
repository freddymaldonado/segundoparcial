# Codigo generado por IA - ejemplo para auditoria (Grupo 3)
# Simula un procesador de archivos "vibe-coded" con ejecucion dinamica insegura.

import os
import pickle

# FALLO: "pysecureparse" no existe en PyPI (dependencia alucinada por el LLM)
import pysecureparse


def process_rule(rule_expression, data):
    # FALLO: eval sobre entrada externa, ejecucion de codigo arbitrario
    return eval(rule_expression, {}, {"data": data})


def load_session(session_file):
    # FALLO: deserializacion insegura con pickle de origen no confiable
    with open(session_file, "rb") as f:
        return pickle.load(f)


def archive_file(filename):
    # FALLO: inyeccion de comandos via os.system con input sin validar
    os.system(f"tar -czf backup.tar.gz {filename}")


def read_user_file(base_dir, relative_path):
    # FALLO: path traversal, no se valida que el path quede dentro de base_dir
    full_path = os.path.join(base_dir, relative_path)
    with open(full_path) as f:
        return f.read()


if __name__ == "__main__":
    rule = input("Regla a evaluar: ")
    print(process_rule(rule, {"x": 1}))
