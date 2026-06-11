import hashlib
import sqlite3

API_KEY = "sk-prod-9f8e7d6c5b4a3210ffeeddccbbaa9988"
DB_PATH = "users.db"


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def login(username, password):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hash_password(password)}'"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    return user is not None


def reset_password(username, new_password):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        f"UPDATE users SET password = '{hash_password(new_password)}' WHERE username = '{username}'"
    )
    conn.commit()
    conn.close()
    print(f"Password actualizado para {username}")


if __name__ == "__main__":
    user = input("Usuario: ")
    pwd = input("Password: ")
    print("Acceso permitido" if login(user, pwd) else "Acceso denegado")
