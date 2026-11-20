"""
ConfigAuditor — Herramienta para auditar configuraciones inseguras.

Revisa archivos de configuración en busca de configuraciones peligrosas:
- DEBUG habilitado en producción
- SECRET_KEY débil o por defecto
- CORS permisivo (Access-Control-Allow-Origin: *)
- Credenciales en archivos de configuración
- Configuraciones de seguridad faltantes
"""

import re
import os


CONFIG_PATTERNS = [
    {
        "name": "DEBUG habilitado",
        "regex": r"""(?:DEBUG)\s*[=:]\s*(?:True|true|1|yes|on)""",
        "severity": "MEDIA",
        "description": "Modo DEBUG habilitado. En producción, esto expone stack traces, "
                       "información del servidor y variables internas a los atacantes.",
        "recommendation": "Establecer DEBUG = False en producción. Usar variables de entorno para controlar el modo.",
    },
    {
        "name": "SECRET_KEY débil/por defecto",
        "regex": r"""SECRET_KEY\s*[=:]\s*['"](?:change[-_]?me|secret|default|password|12345|abcdef|your[-_]?secret|mysecret|test|dev(?:elopment)?|keyboard)['"]""",
        "severity": "CRITICA",
        "description": "SECRET_KEY con valor débil o por defecto. Esto compromete la firma de sesiones, "
                       "CSRF tokens y datos cifrados.",
        "recommendation": "Generar una clave aleatoria de al menos 50 caracteres. Almacenar en variable de entorno.",
    },
    {
        "name": "CORS permisivo (wildcard)",
        "regex": r"""(?:CORS_ORIGIN_ALLOW_ALL|Access-Control-Allow-Origin)\s*[=:]\s*(?:True|\*|['"]?\*['"]?)""",
        "severity": "ALTA",
        "description": "CORS configurado para permitir cualquier origen (*). "
                       "Permite que cualquier sitio web haga solicitudes a la API.",
        "recommendation": "Especificar solo los dominios permitidos en CORS_ALLOWED_ORIGINS.",
    },
    {
        "name": "ALLOWED_HOSTS permisivo",
        "regex": r"""ALLOWED_HOSTS\s*=\s*\[\s*['"]?\*['"]?\s*\]""",
        "severity": "MEDIA",
        "description": "ALLOWED_HOSTS acepta cualquier hostname. Vulnerable a ataques de HTTP Host header.",
        "recommendation": "Especificar los hostnames exactos de producción.",
    },
    {
        "name": "SSL/HTTPS deshabilitado",
        "regex": r"""(?:SECURE_SSL_REDIRECT|SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE)\s*[=:]\s*(?:False|false|0|no)""",
        "severity": "ALTA",
        "description": "Configuraciones de seguridad SSL/HTTPS deshabilitadas. "
                       "Las cookies y datos se transmiten sin cifrar.",
        "recommendation": "Habilitar SSL redirect, secure cookies y HSTS en producción.",
    },
    {
        "name": "Base de datos SQLite en producción",
        "regex": r"""(?:ENGINE|database)\s*[=:]\s*['"].*sqlite3?['"]""",
        "severity": "MEDIA",
        "description": "SQLite configurada como base de datos. No es recomendable para producción "
                       "por limitaciones de concurrencia y seguridad.",
        "recommendation": "Usar PostgreSQL o MySQL en producción con conexiones cifradas.",
    },
    {
        "name": "Puerto de base de datos expuesto",
        "regex": r"""(?:DB_HOST|DATABASE_HOST)\s*[=:]\s*['"]?(?:0\.0\.0\.0)['"]?""",
        "severity": "ALTA",
        "description": "Base de datos escuchando en todas las interfaces (0.0.0.0). "
                       "Accesible desde cualquier red.",
        "recommendation": "Configurar DB para escuchar solo en localhost (127.0.0.1) o red privada.",
    },
    {
        "name": "Credencial en texto plano en config",
        "regex": r"""(?:DB_PASSWORD|DATABASE_PASSWORD|MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD)\s*[=:]\s*['"]([^'"]+)['"]""",
        "severity": "CRITICA",
        "description": "Contraseña de base de datos en archivo de configuración en texto plano.",
        "recommendation": "Usar un gestor de secretos (AWS Secrets Manager, HashiCorp Vault) o variables de entorno seguras.",
    },
    {
        "name": "Logging insuficiente",
        "regex": r"""(?:LOG_LEVEL|LOGGING)\s*[=:]\s*['"]?(?:NONE|OFF|NOTSET|none|off)['"]?""",
        "severity": "MEDIA",
        "description": "Logging deshabilitado o insuficiente. Dificulta la detección de incidentes "
                       "y el análisis forense.",
        "recommendation": "Configurar logging al menos en nivel WARNING para producción.",
    },
    {
        "name": "Rate limiting deshabilitado",
        "regex": r"""(?:RATE_LIMIT|THROTTLE)\s*[=:]\s*(?:False|false|0|none|None|disabled)""",
        "severity": "MEDIA",
        "description": "Rate limiting deshabilitado. La API es vulnerable a ataques de fuerza bruta "
                       "y denegación de servicio.",
        "recommendation": "Implementar rate limiting (ej: 100 requests/minuto por IP).",
    },
]


def audit_config(files: list[str]) -> list[dict]:
    """
    Audita archivos de configuración en busca de configuraciones inseguras.

    Args:
        files: Lista de rutas a archivos de configuración.

    Returns:
        Lista de hallazgos con configuraciones inseguras detectadas.
    """
    findings = []

    for filepath in files:
        if not os.path.isfile(filepath):
            continue

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except (OSError, PermissionError):
            continue

        for line_num, line in enumerate(lines, 1):
            for pattern in CONFIG_PATTERNS:
                if re.search(pattern["regex"], line, re.IGNORECASE):
                    findings.append({
                        "tool": "ConfigAuditor",
                        "file": filepath,
                        "line": line_num,
                        "content": line.strip()[:150],
                        "type": pattern["name"],
                        "severity": pattern["severity"],
                        "description": pattern["description"],
                        "recommendation": pattern["recommendation"],
                        "matched_value": line.strip()[:80],
                    })

    # Deduplicar
    seen = set()
    unique = []
    for f in findings:
        key = (f["file"], f["line"], f["type"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique
