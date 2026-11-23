"""
Módulo de base de datos — EJEMPLO con inyección SQL intencional.
NO usar en producción.
"""

import sqlite3


def get_connection():
    """Obtiene conexión a la base de datos."""
    return sqlite3.connect("app.db")


# ══════════════════════════════════════════════
# VULNERABLE: Inyección SQL por concatenación
# ══════════════════════════════════════════════

def find_user(username):
    """Busca un usuario por nombre — VULNERABLE a SQLi."""
    conn = get_connection()
    cursor = conn.cursor()
    # VULNERABLE: concatenación directa
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result


def search_products(search_term):
    """Busca productos — VULNERABLE a SQLi via f-string."""
    conn = get_connection()
    cursor = conn.cursor()
    # VULNERABLE: f-string en SQL
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{search_term}%'")
    results = cursor.fetchall()
    conn.close()
    return results


def delete_user(user_id):
    """Elimina un usuario — VULNERABLE a SQLi via format()."""
    conn = get_connection()
    cursor = conn.cursor()
    # VULNERABLE: .format() en SQL
    cursor.execute("DELETE FROM users WHERE id = {}".format(user_id))
    conn.commit()
    conn.close()


def update_email(user_id, new_email):
    """Actualiza email — VULNERABLE a SQLi via % formatting."""
    conn = get_connection()
    cursor = conn.cursor()
    # VULNERABLE: % string formatting
    cursor.execute("UPDATE users SET email = '%s' WHERE id = %s" % (new_email, user_id))
    conn.commit()
    conn.close()


# ══════════════════════════════════════════════
# SEGURO: Ejemplo de consulta parametrizada
# ══════════════════════════════════════════════

def find_user_safe(username):
    """Busca un usuario de forma SEGURA con parametrización."""
    conn = get_connection()
    cursor = conn.cursor()
    # SEGURO: consulta parametrizada
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    return result
