"""
LogAnalyzer — Herramienta para analizar logs de acceso en busca de ataques.

Detecta patrones de ataque comunes en archivos de log:
- Intentos de fuerza bruta
- Path traversal
- Inyección SQL en URLs
- Escaneo de directorios
- Intentos de acceso a archivos sensibles
"""

import os
import re
from collections import Counter, defaultdict

from agent.findings import Finding

# Los hallazgos de logs son indicios de ataque (detección), no vulnerabilidades del código
OWASP_MONITORING = "A09:2021 Security Logging and Monitoring Failures"


# Patrones de ataque en logs
ATTACK_PATTERNS = [
    {
        "name": "Intento de SQL Injection en URL",
        "cwe": "CWE-89",
        "regex": r"""(?:UNION\s+SELECT|OR\s+1\s*=\s*1|'\s*OR\s*'|DROP\s+TABLE|;\s*DELETE|SLEEP\s*\(|BENCHMARK\s*\(|0x[0-9a-fA-F]+|CHAR\s*\()""",
        "severity": "CRITICA",
        "description": "Intento de inyección SQL detectado en la URL/parámetros de la solicitud.",
        "recommendation": "Verificar WAF (Web Application Firewall). Bloquear IP origen. Revisar logs de DB.",
    },
    {
        "name": "Path Traversal",
        "cwe": "CWE-22",
        "regex": r"""(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.%2e/|%2e\./|\.\.%5c|\.\.%255c)""",
        "severity": "ALTA",
        "description": "Intento de path traversal (acceso a directorios padre) detectado.",
        "recommendation": "Verificar que la aplicación valida y normaliza rutas de archivo.",
    },
    {
        "name": "Acceso a archivos sensibles",
        "cwe": "CWE-538",
        "regex": r"""(?:/etc/passwd|/etc/shadow|\.env|wp-config\.php|web\.config|\.git/config|\.htaccess|/proc/self|\.ssh/|id_rsa)""",
        "severity": "ALTA",
        "description": "Intento de acceso a archivos sensibles del sistema o aplicación.",
        "recommendation": "Bloquear acceso a archivos sensibles en el servidor web. Revisar permisos.",
    },
    {
        "name": "Escaneo de directorios/admin",
        "cwe": "",
        "regex": r"""(?:/admin|/phpmyadmin|/wp-admin|/wp-login|/administrator|/manager|/console|/actuator|/swagger|/api-docs|/graphql)""",
        "severity": "MEDIA",
        "description": "Escaneo de rutas administrativas comunes detectado.",
        "recommendation": "Ocultar paneles admin. Implementar rate limiting. Usar 2FA en admin.",
    },
    {
        "name": "XSS en URL",
        "cwe": "CWE-79",
        "regex": r"""(?:<script|javascript:|onerror\s*=|onload\s*=|<img\s+src|<iframe|<svg\s+onload|alert\s*\()""",
        "severity": "ALTA",
        "description": "Intento de XSS detectado en parámetros de la URL.",
        "recommendation": "Sanitizar todos los inputs. Implementar Content-Security-Policy.",
    },
    {
        "name": "Command Injection",
        "cwe": "CWE-78",
        "regex": r"""(?:;\s*(?:cat|ls|id|whoami|pwd|wget|curl|nc)\s|`.*`|\$\(.*\)|%0a|%0d|\|\s*(?:cat|id|whoami))""",
        "severity": "CRITICA",
        "description": "Posible intento de inyección de comandos del sistema operativo.",
        "recommendation": "Nunca pasar input del usuario a funciones de ejecución de comandos.",
    },
    {
        "name": "Fuerza bruta (401/403 repetidos)",
        "cwe": "CWE-307",
        "regex": r"""\s(?:401|403)\s""",
        "severity": "MEDIA",
        "description": "Múltiples respuestas 401/403 pueden indicar intento de fuerza bruta.",
        "recommendation": "Implementar rate limiting, bloqueo de cuenta temporal, y CAPTCHA.",
    },
    {
        "name": "Scanner/Bot conocido",
        "cwe": "",
        "regex": r"""(?:sqlmap|nikto|nmap|burpsuite|dirbuster|gobuster|wfuzz|hydra|metasploit|nessus)""",
        "severity": "ALTA",
        "description": "User-Agent de herramienta de escaneo/ataque conocida detectada.",
        "recommendation": "Bloquear IPs de origen. Monitorear actividad posterior.",
    },
]


def _extract_ip(line: str) -> str | None:
    """Extrae la primera dirección IP de una línea de log."""
    match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", line)
    return match.group(1) if match else None


def analyze_logs(files: list[str]) -> list[dict]:
    """
    Analiza archivos de logs en busca de patrones de ataque.

    Args:
        files: Lista de rutas a archivos de log.

    Returns:
        Lista de hallazgos con ataques detectados.
    """
    findings = []
    ip_counter = Counter()         # Contar apariciones por IP
    ip_attacks = defaultdict(list)  # Ataques por IP
    auth_failures = Counter()       # Fallos de autenticación por IP

    for filepath in files:
        if not os.path.isfile(filepath):
            continue

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except (OSError, PermissionError):
            continue

        for line_num, line in enumerate(lines, 1):
            ip = _extract_ip(line)
            if ip:
                ip_counter[ip] += 1

            for pattern in ATTACK_PATTERNS:
                if re.search(pattern["regex"], line, re.IGNORECASE):
                    # Contar fallos de autenticación para detección de fuerza bruta
                    if pattern["name"] == "Fuerza bruta (401/403 repetidos)":
                        if ip:
                            auth_failures[ip] += 1
                        continue  # Se procesará después como grupo

                    findings.append(Finding(
                        tool="LogAnalyzer",
                        file=filepath,
                        line=line_num,
                        content=line.strip()[:200],
                        type=pattern["name"],
                        severity=pattern["severity"],
                        description=pattern["description"],
                        recommendation=pattern["recommendation"],
                        matched_value=f"IP: {ip}" if ip else "IP desconocida",
                        cwe=pattern["cwe"],
                        owasp=OWASP_MONITORING,
                        confidence="MEDIA",
                    ).to_dict())
                    if ip:
                        ip_attacks[ip].append(pattern["name"])

    # Detectar fuerza bruta: IPs con muchos fallos de autenticación
    for ip, count in auth_failures.items():
        if count >= 5:  # Umbral: 5 o más fallos
            severity = "CRITICA" if count >= 20 else "ALTA" if count >= 10 else "MEDIA"
            findings.append(Finding(
                tool="LogAnalyzer",
                file="múltiples logs",
                line=0,
                content=f"IP {ip}: {count} intentos fallidos de autenticación",
                type="Fuerza bruta detectada",
                severity=severity,
                description=f"La IP {ip} tiene {count} respuestas 401/403, indicando "
                            f"un posible ataque de fuerza bruta.",
                recommendation=f"Bloquear IP {ip}. Implementar rate limiting y bloqueo temporal de cuentas.",
                matched_value=f"IP: {ip} ({count} intentos)",
                cwe="CWE-307",
                owasp=OWASP_MONITORING,
                confidence="ALTA",
            ).to_dict())

    # Detectar IPs con múltiples tipos de ataque (atacante activo)
    for ip, attacks in ip_attacks.items():
        unique_attacks = set(attacks)
        if len(unique_attacks) >= 3:
            findings.append(Finding(
                tool="LogAnalyzer",
                file="múltiples logs",
                line=0,
                content=f"IP {ip}: {len(unique_attacks)} tipos de ataque diferentes",
                type="Atacante activo detectado",
                severity="CRITICA",
                description=f"La IP {ip} está realizando múltiples tipos de ataque: "
                            f"{', '.join(sorted(unique_attacks))}. Indica un atacante activo.",
                recommendation=f"Bloquear IP {ip} inmediatamente. Revisar todos los logs. "
                               f"Verificar si hubo acceso exitoso.",
                matched_value=f"IP: {ip}",
                owasp=OWASP_MONITORING,
                confidence="ALTA",
            ).to_dict())

    return findings
