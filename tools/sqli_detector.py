"""
SQLiDetector — Herramienta para detectar vulnerabilidades de inyección SQL.

Analiza el código fuente en busca de patrones peligrosos donde se construyen
consultas SQL mediante concatenación de strings, f-strings, format() o %,
en lugar de usar consultas parametrizadas.

Dos motores:
- Python: análisis del AST. Se buscan llamadas a sinks (`execute`, `raw`, `text`...)
  cuyo SQL se construye dinámicamente, ya sea en línea o a través de una variable
  asignada antes en la misma función. Además se sigue el origen de los datos: si
  provienen de `request.*` o `input()`, el hallazgo se marca como input del usuario
  confirmado. Las consultas parametrizadas no generan hallazgos.
- Otros lenguajes (JS, PHP, Java...): expresiones regulares línea por línea.
"""

import ast
import os
import re

from agent.findings import Finding, SEVERITY_ORDER

CWE_SQLI = "CWE-89"
OWASP_INJECTION = "A03:2021 Injection"


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


# ════════════════════════════════════════════════════════════
# Motor AST (Python)
# ════════════════════════════════════════════════════════════

# Texto que delata una sentencia SQL (evita marcar mensajes como f"Selected {n} items")
SQL_TEXT = re.compile(
    r"\b(?:SELECT\b[\s\S]*\bFROM|INSERT\s+INTO|UPDATE\b[\s\S]*\bSET|DELETE\s+FROM|"
    r"DROP\s+(?:TABLE|DATABASE)|ALTER\s+TABLE|CREATE\s+TABLE|TRUNCATE\s+TABLE)\b",
    re.IGNORECASE,
)

# Métodos/funciones que ejecutan SQL
SQL_SINKS = {"execute", "executemany", "executescript", "raw", "text", "query", "exec_driver_sql"}

# Fuentes de input del usuario
USER_INPUT_ATTRS = {"args", "form", "values", "json", "data", "GET", "POST", "params",
                    "query_params", "cookies", "headers", "files"}

AST_KINDS = {
    "fstring": ("f-string en query SQL", "CRITICA",
                "Consulta SQL construida con f-string. Las variables se insertan directamente "
                "en la consulta sin sanitización.",
                "Reemplazar f-strings por placeholders: cursor.execute('SELECT * FROM users WHERE name = %s', (name,))"),
    "concat": ("Concatenación en query SQL", "CRITICA",
               "Consulta SQL construida con concatenación de strings (+). "
               "Un atacante puede inyectar código SQL arbitrario.",
               "Usar consultas parametrizadas: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"),
    "format": ("format() en query SQL", "CRITICA",
               "Consulta SQL construida con .format(). Permite inyección SQL.",
               "Usar consultas parametrizadas en lugar de .format()."),
    "percent": ("% formatting en query SQL", "CRITICA",
                "Consulta SQL construida con el operador % de Python (no con la parametrización "
                "del driver). Permite inyección SQL.",
                "Pasar los valores como segundo argumento: cursor.execute('... WHERE id = %s', (user_id,))"),
}


def _literal_text(node: ast.AST) -> str:
    """Concatena todo el texto literal de una expresión."""
    return " ".join(
        n.value for n in ast.walk(node)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
    )


def _has_dynamic_part(node: ast.AST) -> bool:
    return any(isinstance(n, (ast.Name, ast.Attribute, ast.Call, ast.Subscript))
               for n in ast.walk(node))


def _classify(node: ast.AST) -> str | None:
    """Devuelve el tipo de construcción dinámica de SQL, o None si no lo es."""
    if isinstance(node, ast.JoinedStr):
        if any(isinstance(v, ast.FormattedValue) for v in node.values) and SQL_TEXT.search(_literal_text(node)):
            return "fstring"
    elif isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Mod) and isinstance(node.left, ast.Constant) \
                and isinstance(node.left.value, str) and SQL_TEXT.search(node.left.value):
            return "percent"
        if isinstance(node.op, ast.Add) and _has_dynamic_part(node) and SQL_TEXT.search(_literal_text(node)):
            # Una concatenación que contiene un f-string se reporta como f-string
            return "fstring" if any(isinstance(n, ast.JoinedStr) for n in ast.walk(node)) else "concat"
    elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
            and node.func.attr == "format" and isinstance(node.func.value, ast.Constant) \
            and isinstance(node.func.value.value, str) and SQL_TEXT.search(node.func.value.value):
        return "format"
    return None


def _is_user_input(node: ast.AST) -> bool:
    """True si la expresión lee directamente de request.* o input()."""
    for n in ast.walk(node):
        if isinstance(n, ast.Attribute) and n.attr in USER_INPUT_ATTRS \
                and isinstance(n.value, ast.Name) and n.value.id == "request":
            return True
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "input":
            return True
    return False


class _Scope:
    """Asignaciones simples (`x = expr`) dentro de una función o del módulo."""

    def __init__(self, body_owner: ast.AST):
        self.assigns: dict[str, list[tuple[int, ast.AST]]] = {}
        for n in ast.walk(body_owner):
            if isinstance(n, ast.Assign):
                for target in n.targets:
                    if isinstance(target, ast.Name):
                        self.assigns.setdefault(target.id, []).append((n.lineno, n.value))
            elif isinstance(n, (ast.AnnAssign, ast.AugAssign)) and isinstance(n.target, ast.Name) and n.value:
                self.assigns.setdefault(n.target.id, []).append((n.lineno, n.value))

    def last_value(self, name: str, before_line: int) -> ast.AST | None:
        candidates = [v for line, v in self.assigns.get(name, []) if line < before_line]
        return candidates[-1] if candidates else None

    def is_tainted(self, node: ast.AST, line: int, depth: int = 0) -> bool:
        """Sigue las variables hacia atrás para saber si provienen de input del usuario."""
        if _is_user_input(node):
            return True
        if depth > 4:
            return False
        for n in ast.walk(node):
            if isinstance(n, ast.Name):
                value = self.last_value(n.id, line)
                if value is not None and self.is_tainted(value, line, depth + 1):
                    return True
        return False


def _sink_name(call: ast.Call) -> str | None:
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr in SQL_SINKS:
        return func.attr
    if isinstance(func, ast.Name) and func.id in {"text"}:
        return func.id
    return None


def _analyze_python_ast(filepath: str, source: str, lines: list[str]) -> list[dict]:
    tree = ast.parse(source, filename=filepath)
    findings = []

    scopes = [tree] + [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    seen_calls = set()
    # Recorrer de la función más interna a la más externa: la primera que vea la llamada gana
    for owner in reversed(scopes):
        scope = _Scope(owner)
        for call in ast.walk(owner):
            if not isinstance(call, ast.Call) or id(call) in seen_calls:
                continue
            seen_calls.add(id(call))
            if _sink_name(call) is None or not call.args:
                continue

            query = call.args[0]
            kind = _classify(query)
            via_variable = None
            if kind is None and isinstance(query, ast.Name):
                value = scope.last_value(query.id, call.lineno)
                if value is not None:
                    kind = _classify(value)
                    via_variable = (query.id, value)
            if kind is None:
                continue

            built = via_variable[1] if via_variable else query
            tainted = scope.is_tainted(built, call.lineno)
            name, severity, description, recommendation = AST_KINDS[kind]

            if via_variable:
                description += (f" La consulta se construye en la variable '{via_variable[0]}' "
                                f"(línea {via_variable[1].lineno}).")
            if tainted:
                name += " (input del usuario)"
                description += " Los datos provienen directamente de la petición del usuario."

            line_text = lines[call.lineno - 1].strip() if call.lineno <= len(lines) else ""
            findings.append(Finding(
                tool="SQLiDetector",
                file=filepath,
                line=call.lineno,
                content=line_text[:150],
                type=name,
                severity=severity,
                description=description,
                recommendation=recommendation,
                matched_value=line_text[:80],
                cwe=CWE_SQLI,
                owasp=OWASP_INJECTION,
                confidence="ALTA" if tainted else "MEDIA",
            ).to_dict())

    return findings


# ════════════════════════════════════════════════════════════
# Motor regex (otros lenguajes y Python que no parsea)
# ════════════════════════════════════════════════════════════

def _analyze_regex(filepath: str, lines: list[str]) -> list[dict]:
    findings = []
    for line_num, line in enumerate(lines, 1):
        matches = [p for p in SQLI_PATTERNS if re.search(p["regex"], line, re.IGNORECASE)]
        if not matches:
            continue
        # Un hallazgo por línea: el patrón de mayor severidad
        pattern = min(matches, key=lambda p: SEVERITY_ORDER.get(p["severity"], 4))
        findings.append(Finding(
            tool="SQLiDetector",
            file=filepath,
            line=line_num,
            content=line.strip()[:150],
            type=pattern["name"],
            severity=pattern["severity"],
            description=pattern["description"],
            recommendation=pattern["recommendation"],
            matched_value=line.strip()[:80],
            cwe=CWE_SQLI,
            owasp=OWASP_INJECTION,
            confidence="MEDIA",
        ).to_dict())
    return findings


def detect_sqli(files: list[str]) -> list[dict]:
    """
    Analiza archivos de código en busca de patrones de inyección SQL.

    Args:
        files: Lista de rutas a archivos de código fuente.

    Returns:
        Lista de hallazgos con posibles vulnerabilidades SQLi.
    """
    findings = []
    valid_extensions = {".py", ".js", ".ts", ".php", ".rb", ".java", ".go"}

    for filepath in files:
        ext = os.path.splitext(filepath)[1].lower()
        if ext not in valid_extensions or not os.path.isfile(filepath):
            continue

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                source = f.read()
        except (OSError, PermissionError):
            continue
        lines = source.splitlines()

        if ext == ".py":
            try:
                findings.extend(_analyze_python_ast(filepath, source, lines))
                continue
            except SyntaxError:
                pass  # Python 2 u otro código que no parsea: usar regex

        findings.extend(_analyze_regex(filepath, lines))

    return findings
