"""
SQLiDetector — Herramienta para detectar vulnerabilidades de inyección SQL.

Analiza el código fuente en busca de patrones peligrosos donde se construyen
consultas SQL mediante concatenación de strings, f-strings, o format(),
en lugar de usar consultas parametrizadas.
"""

import re
import os


# Patrones que indican posible inyección SQL
SQLI_PATTERNS = [
    {
        "name": "Concatenación en query SQL",
        "regex": r"""(?:execute|cursor\.execute|query|raw|db\.execute)\s*\(\s*['"].*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE).*['"]?\s*\+""",
        "severity": "CRITICA",
        "description": "Consulta SQL construida con concatenación de strings (+). "
                       "Un atacante puede inyectar código SQL arbitrario.",
        "recommendation": "Usar consultas parametrizadas: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
    },
    {
        "name": "f-string en query SQL",
        "regex": r"""(?:execute|cursor\.execute|query|raw|db\.execute)\s*\(\s*f['"].*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER).*\{""",
        "severity": "CRITICA",
        "description": "Consulta SQL construida con f-string. Las variables se insertan directamente "
                       "en la consulta sin sanitización.",
        "recommendation": "Reemplazar f-strings por placeholders: cursor.execute('SELECT * FROM users WHERE name = %s', (name,))",
    },
    {
        "name": "format() en query SQL",
        "regex": r"""(?:execute|cursor\.execute|query|raw|db\.execute)\s*\(\s*['"].*(?:SELECT|INSERT|UPDATE|DELETE).*['"]\.format\(""",
        "severity": "CRITICA",
        "description": "Consulta SQL construida con .format(). Permite inyección SQL.",
        "recommendation": "Usar consultas parametrizadas en lugar de .format().",
    },
    {
        "name": "% formatting en query SQL",
        "regex": r"""(?:execute|cursor\.execute|query|raw|db\.execute)\s*\(\s*['"].*(?:SELECT|INSERT|UPDATE|DELETE).*%s.*['"]?\s*%\s*""",
        "severity": "ALTA",
        "description": "Consulta SQL con operador % (string formatting). "
                       "Si se usa fuera de parametrización, es vulnerable.",
        "recommendation": "Verificar que el % se usa como parametrización del driver de DB y no como string formatting de Python.",
    },
    {
        "name": "Query SQL dinámica sin parametrizar",
        "regex": r"""['"](?:SELECT|INSERT|UPDATE|DELETE)\s+.*(?:WHERE|VALUES|SET)\s+.*['"]?\s*\+\s*(?:\w+|['"])""",
        "severity": "ALTA",
        "description": "Query SQL construida dinámicamente con concatenación.",
        "recommendation": "Usar un ORM (SQLAlchemy, Django ORM) o consultas parametrizadas.",
    },
    {
        "name": "SQL en f-string (general)",
        "regex": r"""f['"].*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|JOIN)\s+.*\{.*\}.*['"]""",
        "severity": "ALTA",
        "description": "Sentencia SQL detectada dentro de un f-string con variables interpoladas.",
        "recommendation": "Nunca interpolar variables en sentencias SQL. Usar parametrización.",
    },
    {
        "name": "Django raw() sin parametrizar",
        "regex": r"""\.raw\s*\(\s*f['"]|\.raw\s*\(\s*['"].*['"]\.format\(|\.raw\s*\(\s*['"].*['"]?\s*%""",
        "severity": "CRITICA",
        "description": "Django raw() con interpolación de variables. Bypass completo del ORM.",
        "recommendation": "Usar raw() con params: MyModel.objects.raw('SELECT * WHERE id = %s', [user_id])",
    },
    {
        "name": "SQL con input del usuario",
        "regex": r"""(?:request\.(?:GET|POST|args|form|data|json|params)|input\s*\().*(?:SELECT|INSERT|UPDATE|DELETE)""",
        "severity": "CRITICA",
        "description": "Entrada del usuario utilizada directamente en construcción de query SQL.",
        "recommendation": "NUNCA usar input del usuario directamente en SQL. Validar, sanitizar y parametrizar.",
    },
]


def detect_sqli(files: list[str]) -> list[dict]:
    """
    Analiza archivos de código en busca de patrones de inyección SQL.

    Args:
        files: Lista de rutas a archivos de código fuente.

    Returns:
        Lista de hallazgos con posibles vulnerabilidades SQLi.
    """
    findings = []
    # Solo analizar archivos de código relevantes
    valid_extensions = {".py", ".js", ".ts", ".php", ".rb", ".java", ".go"}

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

        # También buscar patrones multi-línea juntando líneas consecutivas
        full_content = "".join(lines)

        for line_num, line in enumerate(lines, 1):
            # Construir contexto: línea actual + siguiente (para sentencias multi-línea)
            context = line
            if line_num < len(lines):
                context += lines[line_num]  # Incluir siguiente línea

            for pattern in SQLI_PATTERNS:
                if re.search(pattern["regex"], context, re.IGNORECASE | re.DOTALL):
                    findings.append({
                        "tool": "SQLiDetector",
                        "file": filepath,
                        "line": line_num,
                        "content": line.strip()[:150],
                        "type": pattern["name"],
                        "severity": pattern["severity"],
                        "description": pattern["description"],
                        "recommendation": pattern["recommendation"],
                        "matched_value": line.strip()[:80],
                    })

    # Deduplicar hallazgos del mismo archivo y línea
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f["file"], f["line"], f["type"])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    return unique_findings
