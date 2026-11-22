"""
SecretScanner — Herramienta para detectar secretos expuestos en código.

Busca patrones que indiquen credenciales, API keys, tokens, contraseñas
y otros secretos que no deberían estar en el código fuente.
"""

import math
import os
import re

from agent.findings import Finding, mask_in_line, mask_secret

CWE_HARDCODED = "CWE-798"
OWASP_AUTH = "A07:2021 Identification and Authentication Failures"

# Valores que claramente NO son secretos reales (placeholders, plantillas, lecturas de env)
PLACEHOLDER_REGEX = re.compile(
    r"""^(?:
        (?:your|insert|enter|replace|put)[-_ ][\w-]*
      | x{4,}|\*{3,}|\.{3,}|-{3,}
      | <[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\}|%\([^)]+\)s
      | changeme|change[-_]me|placeholder|dummy|sample|todo|tbd|none|null|undefined
      | password|passwd|secret|token|apikey|api[-_]key
    )$""",
    re.IGNORECASE | re.VERBOSE,
)

# Patrones genéricos: basados en el nombre de la variable, no en un formato conocido.
# Para estos se exige una entropía mínima, que filtra valores como "aaaaaaaaaaaaaaaaaaaa".
ENTROPY_CHECKED = {"Generic API Key", "Token Genérico"}
MIN_ENTROPY = 3.0


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
        "confidence": "MEDIA",
        "regex": r"""(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['"]([a-zA-Z0-9_\-]{20,})['"]""",
        "severity": "CRITICA",
        "description": "API key hardcoded en el código fuente",
        "recommendation": "Mover a variables de entorno (.env) y NO incluir .env en el repositorio.",
    },
    {
        "name": "Contraseña Hardcoded",
        "confidence": "MEDIA",
        "regex": r"""(?:password|passwd|pwd|pass)\s*[=:]\s*['"]([^'"]{4,})['"]""",
        "severity": "CRITICA",
        "description": "Contraseña en texto plano en el código",
        "recommendation": "Usar un gestor de secretos o variables de entorno. Nunca hardcodear contraseñas.",
    },
    {
        "name": "Token Genérico",
        "confidence": "MEDIA",
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
        "regex": r"""SECRET_KEY['"\]]*\s*[=:]\s*['"]([^'"]{8,})['"]""",
        "severity": "ALTA",
        "description": "SECRET_KEY del framework web hardcoded",
        "recommendation": "Generar una clave aleatoria fuerte y almacenarla en variables de entorno.",
    },
]


def shannon_entropy(value: str) -> float:
    """Entropía de Shannon en bits por carácter."""
    if not value:
        return 0.0
    counts = {c: value.count(c) for c in set(value)}
    n = len(value)
    return -sum((k / n) * math.log2(k / n) for k in counts.values())


def _is_placeholder(value: str) -> bool:
    stripped = value.strip()
    return bool(PLACEHOLDER_REGEX.match(stripped)) or len(set(stripped)) <= 2


def _secret_value(match: re.Match) -> str:
    """El valor secreto: el primer grupo si el patrón lo captura, si no el match completo."""
    if match.lastindex and match.group(1):
        return match.group(1)
    return match.group(0)


def scan_secrets(files: list[str]) -> list[dict]:
    """
    Escanea una lista de archivos en busca de secretos expuestos.

    Ningún secreto sale de esta función en claro: tanto `content` (la línea)
    como `matched_value` se enmascaran.

    Args:
        files: Lista de rutas a archivos para escanear.

    Returns:
        Lista de hallazgos (dicts de `Finding`).
    """
    findings = []

    for filepath in files:
        if not os.path.isfile(filepath):
            continue

        # Ignorar archivos binarios y muy grandes
        try:
            if os.path.getsize(filepath) > 1_000_000:  # > 1MB, probablemente binario
                continue
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except (OSError, PermissionError):
            continue

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            # Ignorar líneas de comentario que son ejemplos
            if stripped.startswith("#") and "example" in stripped.lower():
                continue

            line_hits = []  # (pattern, secret_value)
            for pattern in SECRET_PATTERNS:
                for match in re.finditer(pattern["regex"], line, re.IGNORECASE):
                    value = _secret_value(match)
                    if _is_placeholder(value):
                        continue
                    if pattern["name"] in ENTROPY_CHECKED and shannon_entropy(value) < MIN_ENTROPY:
                        continue
                    line_hits.append((pattern, value))

            if not line_hits:
                continue

            # Enmascarar TODOS los secretos de la línea antes de guardarla
            masked_line = mask_in_line(stripped, [v for _, v in line_hits])[:120]

            for pattern, value in line_hits:
                findings.append(Finding(
                    tool="SecretScanner",
                    file=filepath,
                    line=line_num,
                    content=masked_line,
                    type=pattern["name"],
                    severity=pattern["severity"],
                    description=pattern["description"],
                    recommendation=pattern["recommendation"],
                    matched_value=mask_secret(value),
                    cwe=CWE_HARDCODED,
                    owasp=OWASP_AUTH,
                    confidence=pattern.get("confidence", "ALTA"),
                ).to_dict())

    return findings
