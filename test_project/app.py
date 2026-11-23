"""
App Flask con vulnerabilidades INTENCIONALES para demostración.
Este archivo es un EJEMPLO de código inseguro. NO usar en producción.
"""

from flask import Flask, request, render_template_string, make_response
import sqlite3
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey123'  # ← SECRET_KEY débil
app.config['DEBUG'] = True  # ← DEBUG habilitado en producción


# ══════════════════════════════════════════════
# VULNERABILIDAD: Inyección SQL
# ══════════════════════════════════════════════
@app.route('/user')
def get_user():
    """Consulta vulnerable a SQL injection."""
    username = request.args.get('name', '')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # VULNERABLE: concatenación de string en query SQL
    cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")
    user = cursor.fetchone()
    conn.close()
    return str(user)


@app.route('/search')
def search():
    """Otra consulta vulnerable con f-string."""
    query = request.args.get('q', '')
    conn = sqlite3.connect('products.db')
    cursor = conn.cursor()
    # VULNERABLE: f-string en query SQL
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{query}%'")
    results = cursor.fetchall()
    conn.close()
    return str(results)


# ══════════════════════════════════════════════
# VULNERABILIDAD: Cross-Site Scripting (XSS)
# ══════════════════════════════════════════════
@app.route('/greet')
def greet():
    """Endpoint vulnerable a XSS via render_template_string."""
    name = request.args.get('name', 'World')
    # VULNERABLE: render_template_string con input del usuario
    return render_template_string(f"<h1>Hola {{ name | safe }}!</h1>", name=name)


@app.route('/comment', methods=['POST'])
def add_comment():
    """Endpoint vulnerable a XSS almacenado."""
    comment = request.form.get('comment', '')
    # VULNERABLE: HTML sin escape
    response = make_response(f"<div class='comment'>{comment}</div>")
    return response


# ══════════════════════════════════════════════
# VULNERABILIDAD: Secretos hardcoded
# ══════════════════════════════════════════════
API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"
DATABASE_URL = "postgresql://admin:SuperSecret123!@db.production.com:5432/myapp"
JWT_SECRET = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"


@app.route('/api/data')
def get_data():
    """Usa API key hardcoded."""
    headers = {
        'Authorization': f'Bearer {API_KEY}'
    }
    return {"status": "ok", "key_prefix": API_KEY[:10]}


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
