"""
SecretScanner — Herramienta para detectar secretos expuestos en código.

Busca patrones que indiquen credenciales, API keys, tokens, contraseñas
y otros secretos que no deberían estar en el código fuente.
"""

import re
import os
from dataclasses import dataclass, field


@dataclass
class SecretFinding:
    """Un secreto encontrado en el código."""
    file: str
    line_number: int
    line_content: str
    secret_type: str
    severity: str  # CRITICA, ALTA, MEDIA, BAJA
    description: str
    recommendation: str


# Patrones de secretos comunes con sus expresiones regulares
SECRET_PATTERNS = [
    {
        "name": "AWS Access Key",
        "regex": r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}",
        "severity": "CRITICA",
        "description": "Clave de acceso AWS detectada",
        "recommendation": "Usar variables de entorno o AWS IAM roles. Rotar la clave inmediatamente.",
    },
    {
        "name": "AWS Secret Key",
        "regex": r"""(?:aws_secret_access_key|aws_secret|secret_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?""",
        "severity": "CRITICA",
        "description": "Clave secreta AWS detectada",
        "recommendation": "Eliminar del código, rotar la clave y usar variables de entorno.",
    },
    {
        "name": "Generic API Key",
        "regex": r"""(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['"]([a-zA-Z0-9_\-]{20,})['"]""",
        "severity": "CRITICA",
        "description": "API key hardcoded en el código fuente",
        "recommendation": "Mover a variables de entorno (.env) y NO incluir .env en el repositorio.",
    },
    {
        "name": "Contraseña Hardcoded",
        "regex": r"""(?:password|passwd|pwd|pass)\s*[=:]\s*['"]([^'"]{4,})['"]""",
        "severity": "CRITICA",
        "description": "Contraseña en texto plano en el código",
        "recommendation": "Usar un gestor de secretos o variables de entorno. Nunca hardcodear contraseñas.",
    },
    {
        "name": "Token Genérico",
        "regex": r"""(?:token|auth_token|access_token|bearer)\s*[=:]\s*['"]([a-zA-Z0-9_\-\.]{20,})['"]""",
        "severity": "ALTA",
        "description": "Token de autenticación detectado en el código",
        "recommendation": "Mover a variables de entorno y rotar el token.",
    },
    {
        "name": "Clave Privada",
        "regex": r"-----BEGIN (?:RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY-----",
        "severity": "CRITICA",
        "description": "Clave privada incluida en el código fuente",
        "recommendation": "Eliminar inmediatamente. Las claves privadas NUNCA deben estar en el repositorio.",
    },
    {
        "name": "Connection String DB",
        "regex": r"""(?:mysql|postgres|postgresql|mongodb|redis)://[^\s'"]+""",
        "severity": "ALTA",
        "description": "String de conexión a base de datos con credenciales",
        "recommendation": "Mover a variables de entorno. Usar conexiones seguras (SSL/TLS).",
    },
    {
        "name": "GitHub Token",
        "regex": r"gh[pousr]_[A-Za-z0-9_]{36,}",
        "severity": "CRITICA",
        "description": "Token de GitHub detectado",
        "recommendation": "Revocar el token inmediatamente y generar uno nuevo. Usar variables de entorno.",
    },
    {
        "name": "JWT Token",
        "regex": r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+",
        "severity": "ALTA",
        "description": "JWT token detectado en código fuente",
        "recommendation": "Los JWT tokens no deben estar hardcodeados. Generarlos dinámicamente.",
    },
    {
        "name": "Slack Webhook/Token",
        "regex": r"xox[baprs]-[0-9A-Za-z\-]{10,}",
        "severity": "ALTA",
        "description": "Token de Slack detectado",
        "recommendation": "Revocar y rotar el token. Usar variables de entorno.",
    },
    {
        "name": "SECRET_KEY (Django/Flask)",
        "regex": r"""SECRET_KEY\s*[=:]\s*['"]([^'"]{8,})['"]""",
        "severity": "ALTA",
        "description": "SECRET_KEY del framework web hardcoded",
        "recommendation": "Generar una clave aleatoria fuerte y almacenarla en variables de entorno.",
    },
]


def scan_secrets(files: list[str]) -> list[dict]:
    """
    Escanea una lista de archivos en busca de secretos expuestos.

    Args:
        files: Lista de rutas a archivos para escanear.

    Returns:
        Lista de hallazgos con información detallada de cada secreto encontrado.
    """
    findings = []

    for filepath in files:
        if not os.path.isfile(filepath):
            continue

        # Ignorar archivos binarios y muy grandes
        try:
            file_size = os.path.getsize(filepath)
            if file_size > 1_000_000:  # > 1MB, probablemente binario
                continue

            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except (OSError, PermissionError):
            continue

        for line_num, line in enumerate(lines, 1):
            # Ignorar líneas de comentario que son ejemplos
            stripped = line.strip()
            if stripped.startswith("#") and "example" in stripped.lower():
                continue

            for pattern in SECRET_PATTERNS:
                matches = re.finditer(pattern["regex"], line, re.IGNORECASE)
                for match in matches:
                    # Enmascarar el secreto para el reporte
                    secret_value = match.group(0)
                    masked = secret_value[:8] + "****" + secret_value[-4:] if len(secret_value) > 12 else "****"

                    findings.append({
                        "tool": "SecretScanner",
                        "file": filepath,
                        "line": line_num,
                        "content": line.strip()[:120],  # Truncar para seguridad
                        "type": pattern["name"],
                        "severity": pattern["severity"],
                        "description": pattern["description"],
                        "recommendation": pattern["recommendation"],
                        "matched_value": masked,
                    })

    return findings
