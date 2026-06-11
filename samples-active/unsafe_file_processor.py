import os
import pickle

import pysecureparse


def process_rule(rule_expression, data):
    return eval(rule_expression, {}, {"data": data})


def load_session(session_file):
    with open(session_file, "rb") as f:
        return pickle.load(f)


def archive_file(filename):
    os.system(f"tar -czf backup.tar.gz {filename}")


def read_user_file(base_dir, relative_path):
    full_path = os.path.join(base_dir, relative_path)
    with open(full_path) as f:
        return f.read()


if __name__ == "__main__":
    rule = input("Regla a evaluar: ")
    print(process_rule(rule, {"x": 1}))
