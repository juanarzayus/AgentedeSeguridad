"""
XSSDetector — Herramienta para detectar vulnerabilidades Cross-Site Scripting.

Busca patrones en código HTML, JavaScript y templates donde el contenido
generado dinámicamente no se sanitiza antes de renderizarse en el navegador.
"""

import os
import re

from agent.findings import Finding
from tools.source_context import python_views

OWASP_INJECTION = "A03:2021 Injection"


# "kind": en archivos Python, los patrones "call" se buscan en el código (sin el contenido
# de los strings) y los "markup" solo dentro de strings que parecen HTML/plantillas.
# Así, el texto "eval() ejecuta código" de una descripción no se confunde con una llamada.
XSS_PATTERNS = [
    {
        "name": "innerHTML sin sanitización",
        "kind": "markup",
        "cwe": "CWE-79",
        "regex": r"""\.innerHTML\s*=\s*(?!['"]<)""",
        "severity": "ALTA",
        "description": "Asignación directa a innerHTML con contenido dinámico. "
                       "Permite inyección de scripts maliciosos.",
        "recommendation": "Usar textContent en lugar de innerHTML, o sanitizar con DOMPurify.",
    },
    {
        "name": "document.write()",
        "kind": "markup",
        "cwe": "CWE-79",
        "regex": r"""document\.write\s*\(""",
        "severity": "ALTA",
        "description": "document.write() puede inyectar HTML/JS arbitrario en el DOM.",
        "recommendation": "Usar métodos seguros del DOM como createElement/appendChild.",
    },
    {
        "name": "eval() con input dinámico",
        "kind": "call",
        "cwe": "CWE-95",
        "regex": r"""eval\s*\(\s*(?!['"])""",
        "severity": "CRITICA",
        "description": "eval() ejecuta código JavaScript arbitrario. Si recibe input del usuario, "
                       "permite ejecución remota de código.",
        "recommendation": "Eliminar eval(). Usar JSON.parse() para datos, o alternativas seguras.",
    },
    {
        "name": "Jinja2/Flask sin escape (|safe)",
        "kind": "markup",
        "cwe": "CWE-79",
        "regex": r"""\{\{.*\|\s*safe\s*\}\}""",
        "severity": "ALTA",
        "description": "Template Jinja2 con filtro |safe desactiva el auto-escape. "
                       "Si el contenido viene del usuario, permite XSS.",
        "recommendation": "Eliminar |safe o asegurar que el contenido está sanitizado antes de usarlo.",
    },
    {
        "name": "Template sin escape ({% autoescape false %})",  # secscan: ignore (nombre de la regla, no una plantilla)
        "kind": "markup",
        "cwe": "CWE-79",
        "regex": r"""\{%\s*autoescape\s+false\s*%\}""",
        "severity": "ALTA",
        "description": "Auto-escape desactivado en bloque de template. Todo el contenido dinámico "
                       "se renderiza sin protección.",
        "recommendation": "Mantener autoescape activado. Sanitizar manualmente solo donde sea necesario.",
    },
    {
        "name": "render_template_string() en Flask",
        "kind": "call",
        "cwe": "CWE-1336",
        "regex": r"""render_template_string\s*\(""",
        "severity": "CRITICA",
        "description": "render_template_string() con input del usuario permite Server-Side Template "
                       "Injection (SSTI), que lleva a ejecución remota de código.",
        "recommendation": "Usar render_template() con archivos .html. Nunca construir templates dinámicamente.",
    },
    {
        "name": "jQuery .html() con datos dinámicos",
        "kind": "markup",
        "cwe": "CWE-79",
        "regex": r"""\$\(.*\)\.html\s*\(\s*(?!['"])""",
        "severity": "ALTA",
        "description": "jQuery .html() inyecta HTML sin sanitización, similar a innerHTML.",
        "recommendation": "Usar .text() en lugar de .html(), o sanitizar el input.",
    },
    {
        "name": "Respuesta HTTP sin Content-Type",
        "kind": "call",
        "cwe": "CWE-79",
        "regex": r"""(?:make_response|Response)\s*\((?!\s*(?:render_template|jsonify)\b)[^)]*\)(?!.*content_type)""",
        "severity": "MEDIA",
        "description": "Respuesta HTTP sin Content-Type explícito puede ser interpretada como HTML.",
        "recommendation": "Establecer Content-Type explícitamente: response.headers['Content-Type'] = 'application/json'",
    },
    {
        "name": "Markup.format() en Flask/Jinja2",
        "kind": "call",
        "cwe": "CWE-79",
        "regex": r"""Markup\s*\(.*\.format\(""",
        "severity": "ALTA",
        "description": "Markup() con .format() puede inyectar HTML si las variables no están escapadas.",
        "recommendation": "Usar Markup.format() (el método de Markup, no de str) o escapar variables manualmente.",
    },
]


def detect_xss(files: list[str]) -> list[dict]:
    """
    Analiza archivos en busca de vulnerabilidades XSS.

    Args:
        files: Lista de rutas a archivos para analizar.

    Returns:
        Lista de hallazgos con vulnerabilidades XSS detectadas.
    """
    findings = []
    valid_extensions = {".py", ".js", ".ts", ".jsx", ".tsx", ".html", ".htm", ".vue", ".svelte", ".php"}

    for filepath in files:
        ext = os.path.splitext(filepath)[1].lower()
        if ext not in valid_extensions:
            continue
        if not os.path.isfile(filepath):
            continue

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except (OSError, PermissionError):
            continue

        views = python_views("".join(lines)) if ext == ".py" else None

        for line_num, line in enumerate(lines, 1):
            for pattern in XSS_PATTERNS:
                subject = line
                if views is not None:
                    if line_num in views.doc_lines:
                        continue
                    if pattern["kind"] == "call":
                        subject = views.code[line_num - 1]
                    elif line_num not in views.markup_lines:
                        continue
                if re.search(pattern["regex"], subject, re.IGNORECASE):
                    findings.append(Finding(
                        tool="XSSDetector",
                        file=filepath,
                        line=line_num,
                        content=line.strip()[:150],
                        type=pattern["name"],
                        severity=pattern["severity"],
                        description=pattern["description"],
                        recommendation=pattern["recommendation"],
                        matched_value=line.strip()[:80],
                        cwe=pattern["cwe"],
                        owasp=OWASP_INJECTION,
                        confidence="MEDIA",
                    ).to_dict())

    return findings
