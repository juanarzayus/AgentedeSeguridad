"""
DependencyAudit — Herramienta para auditar dependencias inseguras.

Revisa archivos de dependencias (requirements.txt, package.json)
contra una base de datos local de vulnerabilidades conocidas (CVEs).

Cómo se interpreta cada declaración de versión:
- Versión exacta (`flask==2.2.0`, `"express": "4.17.1"`): se compara directamente.
- Rango con cota inferior (`flask>=2.0`, `^4.17.0`, `~=2.0`): si la cota inferior
  ya está corregida no hay hallazgo; si no, el rango *permite* instalar una versión
  vulnerable y se reporta con severidad BAJA.
- Rango acotado por arriba (`flask<2.3`): si ninguna versión permitida está
  corregida, se reporta con la severidad completa del CVE.
- Sin versión (`flask`): se reporta como dependencia sin fijar (BAJA).
"""

import json
import os
import re

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

from agent.findings import Finding

CWE_VULN_COMPONENT = "CWE-1395"  # Dependency on Vulnerable Third-Party Component
OWASP_COMPONENTS = "A06:2021 Vulnerable and Outdated Components"

# Una versión "infinitamente nueva" para saber si un rango no tiene cota superior
_FAR_FUTURE = Version("99999")


# Base de datos local de vulnerabilidades conocidas (subconjunto real, mantenido a mano).
# En producción usarías la API de OSV, Snyk, o GitHub Advisory DB.
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


def normalize_name(name: str) -> str:
    """Normaliza nombres de paquete según PEP 503 (Flask_SQLAlchemy == flask-sqlalchemy)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse_requirements_txt(filepath: str) -> list[tuple[str, SpecifierSet, int]]:
    """Parsea un requirements.txt y devuelve [(paquete, especificador, línea)]."""
    packages = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line_num, raw in enumerate(f, 1):
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            try:
                req = Requirement(line)
            except InvalidRequirement:
                continue
            packages.append((normalize_name(req.name), req.specifier, line_num))
    return packages


def _npm_to_specifier(ver: str) -> SpecifierSet | None:
    """Traduce una versión de npm a un SpecifierSet de PEP 440 (aproximación)."""
    ver = ver.strip()
    if ver in {"", "*", "latest", "x"}:
        return SpecifierSet()
    match = re.match(r"^(\^|~|>=|>|<=|<|=)?\s*v?(\d+(?:\.\d+){0,2})", ver)
    if not match:
        return None  # git URLs, file:, alias, etc.
    op, number = match.groups()
    if op in {"^", "~", ">=", "="} or op is None:
        return SpecifierSet(f"=={number}" if op in {None, "="} else f">={number}")
    return SpecifierSet(f"{op}{number}")


def _parse_package_json(filepath: str) -> list[tuple[str, SpecifierSet, int]]:
    """Parsea un package.json y devuelve [(paquete, especificador, línea)]."""
    packages = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            text = f.read()
        data = json.loads(text)
    except (json.JSONDecodeError, OSError):
        return packages

    lines = text.splitlines()
    for dep_key in ["dependencies", "devDependencies"]:
        for name, ver in data.get(dep_key, {}).items():
            spec = _npm_to_specifier(str(ver))
            if spec is None:
                continue
            line_num = next((i for i, l in enumerate(lines, 1) if f'"{name}"' in l), 0)
            packages.append((name.lower(), spec, line_num))
    return packages


def _lower_bound(spec: SpecifierSet) -> Version | None:
    """La menor versión que el especificador declara como mínima (si existe)."""
    bounds = []
    for s in spec:
        if s.operator in {"==", "===", ">=", ">", "~="} and "*" not in s.version:
            try:
                bounds.append(Version(s.version))
            except InvalidVersion:
                pass
    return max(bounds) if bounds else None


def _exact_version(spec: SpecifierSet) -> Version | None:
    for s in spec:
        if s.operator in {"==", "==="} and "*" not in s.version:
            try:
                return Version(s.version)
            except InvalidVersion:
                return None
    return None


def assess(spec: SpecifierSet, fixed_in: str) -> str:
    """
    Evalúa un especificador de versión frente a una vulnerabilidad corregida en `fixed_in`.

    Returns:
        "vulnerable"    — todas las versiones permitidas están afectadas.
        "range_allows"  — el rango permite instalar una versión afectada.
        "unpinned"      — no hay restricción de versión.
        "safe"          — ninguna versión permitida está afectada.
    """
    fixed = Version(fixed_in)

    exact = _exact_version(spec)
    if exact is not None:
        return "vulnerable" if exact < fixed else "safe"

    if len(spec) == 0:
        return "unpinned"

    lower = _lower_bound(spec)
    if lower is not None and lower >= fixed:
        return "safe"

    # ¿Existe alguna versión corregida permitida por el rango?
    allows_fixed = spec.contains(fixed, prereleases=True) or spec.contains(_FAR_FUTURE, prereleases=True)
    return "range_allows" if allows_fixed else "vulnerable"


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
        if basename == "requirements.txt":
            packages = _parse_requirements_txt(filepath)
        elif basename == "package.json":
            packages = _parse_package_json(filepath)
        else:
            continue

        for pkg_name, spec, line_num in packages:
            vulns = VULNERABILITY_DB.get(pkg_name, [])
            declared = f"{pkg_name}{spec}" if len(spec) else pkg_name

            if vulns and len(spec) == 0:
                cves = ", ".join(v["cve"] for v in vulns)
                findings.append(Finding(
                    tool="DependencyAudit",
                    file=filepath,
                    line=line_num,
                    content=declared,
                    type="Dependencia sin versión fijada",
                    severity="BAJA",
                    description=f"{pkg_name} no fija versión. Según lo que se instale podría "
                                f"estar afectado por: {cves}.",
                    recommendation=f"Fijar la versión de {pkg_name} (p. ej. con un lockfile o "
                                   f"pip-compile) en una versión corregida.",
                    matched_value=declared,
                    cwe=CWE_VULN_COMPONENT,
                    owasp=OWASP_COMPONENTS,
                    confidence="BAJA",
                ).to_dict())
                continue

            for vuln in vulns:
                verdict = assess(spec, vuln["fixed_in"])
                if verdict == "safe":
                    continue

                if verdict == "vulnerable":
                    severity, confidence = vuln["severity"], "ALTA"
                    description = f"{declared}: {vuln['description']}"
                    vtype = f"CVE: {vuln['cve']}"
                else:  # range_allows
                    severity, confidence = "BAJA", "MEDIA"
                    description = (f"{declared} permite instalar versiones anteriores a "
                                   f"{vuln['fixed_in']}, afectadas por {vuln['cve']}: "
                                   f"{vuln['description']}")
                    vtype = f"CVE: {vuln['cve']} (rango permisivo)"

                findings.append(Finding(
                    tool="DependencyAudit",
                    file=filepath,
                    line=line_num,
                    content=declared,
                    type=vtype,
                    severity=severity,
                    description=description,
                    recommendation=f"Actualizar {pkg_name} a versión {vuln['fixed_in']} o superior.",
                    matched_value=declared,
                    cwe=CWE_VULN_COMPONENT,
                    owasp=OWASP_COMPONENTS,
                    confidence=confidence,
                ).to_dict())

    return findings
