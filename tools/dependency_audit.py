"""
DependencyAudit — Herramienta para auditar dependencias inseguras.

Revisa archivos de dependencias (requirements.txt, package.json)
contra una base de datos local de vulnerabilidades conocidas (CVEs).
"""

import os
import re
from packaging import version as pkg_version


# Base de datos local de vulnerabilidades conocidas (simulada pero realista)
# En producción usarías la API de OSV, Snyk, o GitHub Advisory DB
VULNERABILITY_DB = {
    # Paquetes Python
    "flask": [
        {
            "cve": "CVE-2023-30861",
            "affected_versions": "<2.3.2",
            "severity": "ALTA",
            "description": "Cookie de sesión puede ser robada vía response splitting",
            "fixed_in": "2.3.2",
        },
    ],
    "django": [
        {
            "cve": "CVE-2023-46695",
            "affected_versions": "<4.2.7",
            "severity": "ALTA",
            "description": "Denegación de servicio vía campo de archivo large",
            "fixed_in": "4.2.7",
        },
        {
            "cve": "CVE-2024-24680",
            "affected_versions": "<4.2.10",
            "severity": "MEDIA",
            "description": "ReDoS en intcomma template filter",
            "fixed_in": "4.2.10",
        },
    ],
    "requests": [
        {
            "cve": "CVE-2023-32681",
            "affected_versions": "<2.31.0",
            "severity": "MEDIA",
            "description": "Fuga de headers de autenticación en redirecciones",
            "fixed_in": "2.31.0",
        },
    ],
    "urllib3": [
        {
            "cve": "CVE-2023-45803",
            "affected_versions": "<2.0.7",
            "severity": "MEDIA",
            "description": "Request body no limpiado en redirecciones cross-origin",
            "fixed_in": "2.0.7",
        },
    ],
    "sqlalchemy": [
        {
            "cve": "CVE-2023-XXXX",
            "affected_versions": "<1.4.46",
            "severity": "ALTA",
            "description": "Posible inyección SQL en ciertas construcciones de consultas",
            "fixed_in": "1.4.46",
        },
    ],
    "jinja2": [
        {
            "cve": "CVE-2024-22195",
            "affected_versions": "<3.1.3",
            "severity": "MEDIA",
            "description": "XSS en xmlattr filter con claves de atributos controladas por atacante",
            "fixed_in": "3.1.3",
        },
    ],
    "werkzeug": [
        {
            "cve": "CVE-2023-46136",
            "affected_versions": "<3.0.1",
            "severity": "ALTA",
            "description": "Denegación de servicio vía consumo excesivo de recursos",
            "fixed_in": "3.0.1",
        },
    ],
    "pillow": [
        {
            "cve": "CVE-2023-50447",
            "affected_versions": "<10.2.0",
            "severity": "CRITICA",
            "description": "Ejecución de código arbitrario en ImageMath.eval",
            "fixed_in": "10.2.0",
        },
    ],
    "cryptography": [
        {
            "cve": "CVE-2023-49083",
            "affected_versions": "<41.0.6",
            "severity": "ALTA",
            "description": "NULL pointer dereference al cargar certificados PKCS7",
            "fixed_in": "41.0.6",
        },
    ],
    "numpy": [
        {
            "cve": "CVE-2023-XXXX",
            "affected_versions": "<1.22.0",
            "severity": "MEDIA",
            "description": "Buffer overflow en operaciones de array",
            "fixed_in": "1.22.0",
        },
    ],
    # Paquetes npm
    "express": [
        {
            "cve": "CVE-2024-29041",
            "affected_versions": "<4.19.2",
            "severity": "MEDIA",
            "description": "Open redirect en res.redirect con URLs malformadas",
            "fixed_in": "4.19.2",
        },
    ],
    "lodash": [
        {
            "cve": "CVE-2021-23337",
            "affected_versions": "<4.17.21",
            "severity": "ALTA",
            "description": "Command injection en template function",
            "fixed_in": "4.17.21",
        },
    ],
    "axios": [
        {
            "cve": "CVE-2023-45857",
            "affected_versions": "<1.6.0",
            "severity": "MEDIA",
            "description": "CSRF via XSRF-TOKEN cookie exposure cross-site",
            "fixed_in": "1.6.0",
        },
    ],
}


def _parse_requirements_txt(filepath: str) -> list[tuple[str, str]]:
    """Parsea un requirements.txt y devuelve [(paquete, versión)]."""
    packages = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Parsear formato: paquete==version, paquete>=version, paquete
            match = re.match(r"([a-zA-Z0-9_\-\.]+)\s*(?:[=<>!~]+\s*)?([\d][^\s,;]*)?", line)
            if match:
                name = match.group(1).lower().replace("-", "").replace("_", "")
                ver = match.group(2) if match.group(2) else "unknown"
                packages.append((match.group(1).lower(), ver))
    return packages


def _parse_package_json(filepath: str) -> list[tuple[str, str]]:
    """Parsea un package.json y devuelve [(paquete, versión)]."""
    import json
    packages = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        for dep_key in ["dependencies", "devDependencies"]:
            deps = data.get(dep_key, {})
            for name, ver in deps.items():
                # Limpiar prefijos como ^, ~, >=
                clean_ver = re.sub(r"^[\^~>=<]+", "", ver)
                packages.append((name.lower(), clean_ver))
    except (json.JSONDecodeError, OSError):
        pass
    return packages


def _is_vulnerable(installed_ver: str, affected_spec: str) -> bool:
    """Verifica si una versión instalada es afectada por la vulnerabilidad."""
    if installed_ver == "unknown":
        return True  # Si no sabemos la versión, advertir

    try:
        # Parsear la especificación "< X.Y.Z"
        match = re.match(r"<\s*([\d\.]+)", affected_spec)
        if match:
            threshold = match.group(1)
            return pkg_version.parse(installed_ver) < pkg_version.parse(threshold)
    except Exception:
        return False
    return False


def audit_dependencies(files: list[str]) -> list[dict]:
    """
    Audita archivos de dependencias contra la base de datos de vulnerabilidades.

    Args:
        files: Lista de rutas a archivos de dependencias.

    Returns:
        Lista de hallazgos con vulnerabilidades encontradas.
    """
    findings = []

    for filepath in files:
        if not os.path.isfile(filepath):
            continue

        basename = os.path.basename(filepath).lower()

        # Parsear según tipo de archivo
        if basename == "requirements.txt":
            packages = _parse_requirements_txt(filepath)
        elif basename == "package.json":
            packages = _parse_package_json(filepath)
        else:
            continue

        # Verificar cada paquete contra la DB de vulnerabilidades
        for pkg_name, pkg_ver in packages:
            # Normalizar nombre para búsqueda
            normalized = pkg_name.lower().replace("-", "").replace("_", "")
            db_key = pkg_name.lower()

            # Buscar en la base de datos
            vulns = VULNERABILITY_DB.get(db_key, [])
            for vuln in vulns:
                if _is_vulnerable(pkg_ver, vuln["affected_versions"]):
                    findings.append({
                        "tool": "DependencyAudit",
                        "file": filepath,
                        "line": 0,
                        "content": f"{pkg_name}=={pkg_ver}",
                        "type": f"CVE: {vuln['cve']}",
                        "severity": vuln["severity"],
                        "description": f"{pkg_name} {pkg_ver}: {vuln['description']}",
                        "recommendation": f"Actualizar {pkg_name} a versión {vuln['fixed_in']} o superior.",
                        "matched_value": f"{pkg_name}=={pkg_ver}",
                    })

    return findings
