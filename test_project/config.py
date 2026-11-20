"""
Configuración del proyecto — EJEMPLO con vulnerabilidades intencionales.
⚠️  NO usar en producción.
"""

import os

# ══════════════════════════════════════════════
# VULNERABILIDAD: Configuraciones inseguras
# ══════════════════════════════════════════════

# ⚠️ DEBUG habilitado — expone información interna
DEBUG = True

# ⚠️ SECRET_KEY débil y predecible
SECRET_KEY = "change-me"

# ⚠️ CORS permisivo — cualquier sitio puede hacer requests
CORS_ORIGIN_ALLOW_ALL = True

# ⚠️ Credenciales de base de datos en texto plano
DB_HOST = "0.0.0.0"
DB_PORT = 5432
DB_NAME = "production_db"
DB_USER = "admin"
DB_PASSWORD = "P@ssw0rd2024!"

# ⚠️ ALLOWED_HOSTS permisivo
ALLOWED_HOSTS = ["*"]

# ⚠️ SSL deshabilitado
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False

# ⚠️ Logging insuficiente
LOG_LEVEL = "NONE"

# ⚠️ Rate limiting deshabilitado
RATE_LIMIT = False

# ⚠️ AWS credentials hardcoded
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Base de datos SQLite (no recomendada para producción)
DATABASE_ENGINE = "sqlite3"
DATABASE_NAME = "./db.sqlite3"
