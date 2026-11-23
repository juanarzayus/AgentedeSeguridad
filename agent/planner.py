"""
Planner — Motor de razonamiento y planificación del agente.

El Planner analiza el objetivo del usuario (escanear un proyecto),
examina el contexto (qué archivos existen, qué tipo de proyecto es),
y decide qué herramientas ejecutar y en qué orden.

Utiliza un sistema de reglas + heurísticas para simular razonamiento,
similar a cómo un LLM planificaría una secuencia de acciones.
"""

import fnmatch
import os
import re
from pathlib import Path
from dataclasses import dataclass, field

IGNORE_FILE = ".secscanignore"
DEFAULT_IGNORED_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".tox"}


def load_ignore_patterns(target_path: str) -> list[str]:
    """
    Lee `.secscanignore` (un patrón glob por línea, `#` para comentarios).

    Los patrones se comparan contra la ruta relativa al proyecto y contra el
    nombre del archivo, p. ej. `tests/*`, `*.min.js`, `docs/`.
    """
    path = os.path.join(target_path, IGNORE_FILE)
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [l.strip() for l in f if l.strip() and not l.lstrip().startswith("#")]


GENERATED_MARKERS = ('<meta name="generator" content="SecScan Agent">', '"agent": "SecScan Agent"')
_LEGACY_REPORT = re.compile(r"^security_report_\d{8}_\d{6}\.(?:html|json|txt)$")


def is_generated_report(filepath: str) -> bool:
    """
    True si el archivo es un reporte creado por SecScan. Analizarlo produciría
    cientos de falsos positivos: el reporte cita el código vulnerable que encontró.
    """
    name = os.path.basename(filepath)
    if not name.endswith((".html", ".json", ".txt")):
        return False
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            head = f.read(4096)
    except OSError:
        return False
    # Reportes de versiones anteriores (sin la marca): se reconocen por su nombre exacto
    return any(m in head for m in GENERATED_MARKERS) or bool(_LEGACY_REPORT.match(name))


def is_ignored(rel_path: str, patterns: list[str]) -> bool:
    rel_path = rel_path.replace(os.sep, "/")
    name = rel_path.rsplit("/", 1)[-1]
    for pattern in patterns:
        if pattern.endswith("/"):
            if rel_path.startswith(pattern) or f"/{pattern}" in f"/{rel_path}":
                return True
        elif fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(name, pattern):
            return True
    return False


@dataclass
class ScanContext:
    """Contexto recopilado sobre el proyecto a escanear."""
    target_path: str
    logs_path: str | None = None
    file_extensions: set = field(default_factory=set)
    has_requirements: bool = False
    has_package_json: bool = False
    has_config_files: bool = False
    has_env_files: bool = False
    has_python_files: bool = False
    has_js_files: bool = False
    has_html_files: bool = False
    has_sql_files: bool = False
    has_log_files: bool = False
    total_files: int = 0
    file_list: list = field(default_factory=list)
    log_file_list: list = field(default_factory=list)
    ignored_files: int = 0


@dataclass
class ActionPlan:
    """Plan de acción generado por el Planner."""
    steps: list[dict] = field(default_factory=list)
    reasoning: list[str] = field(default_factory=list)
    context: ScanContext | None = None
    allowed_tools: list[str] | None = None
    skipped: list[str] = field(default_factory=list)

    def add_step(self, tool_name: str, params: dict, reason: str) -> None:
        """Agrega un paso al plan con su justificación (si el skill lo permite)."""
        if self.allowed_tools is not None and tool_name not in self.allowed_tools:
            self.skipped.append(tool_name)
            self.reasoning.append(f"Omitido: {tool_name} — no forma parte del skill seleccionado.")
            return
        self.steps.append({
            "tool": tool_name,
            "params": params,
            "reason": reason,
            "order": len(self.steps) + 1,
        })
        self.reasoning.append(f"Paso {len(self.steps)}: {reason}")

    def to_dict(self) -> dict:
        return {
            "total_steps": len(self.steps),
            "steps": self.steps,
            "reasoning": self.reasoning,
            "skipped_tools": self.skipped,
        }


class Planner:
    """
    Motor de planificación del agente.

    Analiza el directorio objetivo, determina el tipo de proyecto,
    y genera un plan de acción con las herramientas a ejecutar.
    
    El proceso de razonamiento sigue esta cadena:
    1. OBSERVAR — Escanear el directorio y recopilar contexto
    2. RAZONAR — Determinar qué análisis son relevantes
    3. PLANIFICAR — Generar una secuencia ordenada de acciones
    """

    # Extensiones de archivo relevantes para cada tipo de análisis
    CODE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".php", ".rb", ".go", ".cs"}
    WEB_EXTENSIONS = {".html", ".htm", ".js", ".jsx", ".tsx", ".vue", ".svelte"}
    CONFIG_FILES = {
        "config.py", "settings.py", "config.json", "config.yaml", "config.yml",
        ".env", ".env.local", ".env.production", "docker-compose.yml",
        "Dockerfile", "nginx.conf", "apache.conf", "web.config",
    }
    DEPENDENCY_FILES = {"requirements.txt", "Pipfile", "pyproject.toml", "package.json", "Gemfile", "go.mod", "pom.xml"}

    def analyze_context(self, target_path: str, logs_path: str | None = None) -> ScanContext:
        """
        PASO 1: OBSERVAR — Escanea el directorio y recopila contexto.
        
        Recorre el directorio objetivo para entender qué tipo de proyecto es
        y qué archivos contiene.
        """
        ctx = ScanContext(target_path=target_path, logs_path=logs_path)
        target = Path(target_path)

        if not target.exists():
            raise FileNotFoundError(f"Directorio no encontrado: {target_path}")

        ignore_patterns = load_ignore_patterns(target_path)
        seen: set[Path] = set()

        # Recorrer archivos del proyecto
        for root, dirs, files in os.walk(target_path):
            # Ignorar directorios irrelevantes
            dirs[:] = [d for d in dirs if d not in DEFAULT_IGNORED_DIRS]
            for f in files:
                filepath = os.path.join(root, f)
                if f == IGNORE_FILE:
                    continue
                if is_ignored(os.path.relpath(filepath, target_path), ignore_patterns) \
                        or is_generated_report(filepath):
                    ctx.ignored_files += 1
                    continue
                seen.add(Path(filepath).resolve())
                ext = os.path.splitext(f)[1].lower()

                ctx.file_list.append(filepath)
                ctx.file_extensions.add(ext)
                ctx.total_files += 1

                # Detectar tipos de archivo
                if ext == ".py":
                    ctx.has_python_files = True
                elif ext in {".js", ".ts", ".jsx", ".tsx"}:
                    ctx.has_js_files = True
                elif ext in {".html", ".htm"}:
                    ctx.has_html_files = True
                elif ext == ".sql":
                    ctx.has_sql_files = True

                # Detectar archivos especiales
                if f in self.DEPENDENCY_FILES:
                    ctx.has_requirements = True
                    if f == "package.json":
                        ctx.has_package_json = True
                if f.lower() in {n.lower() for n in self.CONFIG_FILES}:
                    ctx.has_config_files = True
                if f.startswith(".env"):
                    ctx.has_env_files = True

        # Logs: solo los del directorio indicado con --logs (comparando rutas reales,
        # no strings, para que funcione con rutas relativas/absolutas mezcladas)
        if logs_path and os.path.isdir(logs_path):
            for f in sorted(os.listdir(logs_path)):
                filepath = os.path.join(logs_path, f)
                if os.path.isfile(filepath) and (f.endswith(".log") or f.endswith(".txt")):
                    ctx.log_file_list.append(filepath)
                    ctx.has_log_files = True
                    if Path(filepath).resolve() not in seen:
                        ctx.file_list.append(filepath)

        return ctx

    def create_plan(self, ctx: ScanContext, allowed_tools: list[str] | None = None) -> ActionPlan:
        """
        PASO 2 y 3: RAZONAR + PLANIFICAR

        Basándose en el contexto observado, decide qué herramientas ejecutar
        y en qué orden. Prioriza por impacto de seguridad.

        Args:
            ctx: Contexto observado del proyecto.
            allowed_tools: Herramientas que el skill permite usar. None = todas.
        """
        plan = ActionPlan(context=ctx, allowed_tools=allowed_tools)

        # --- Razonamiento del agente ---

        # SIEMPRE: Escanear secretos (prioridad máxima)
        # Razonamiento: Los secretos expuestos son la vulnerabilidad más crítica
        # porque dan acceso directo a sistemas.
        code_files = [f for f in ctx.file_list if os.path.splitext(f)[1] in self.CODE_EXTENSIONS]
        config_files = [f for f in ctx.file_list if os.path.basename(f).lower() in {n.lower() for n in self.CONFIG_FILES}]
        env_files = [f for f in ctx.file_list if os.path.basename(f).startswith(".env")]
        all_scan_files = sorted(set(code_files + config_files + env_files))

        if all_scan_files:
            plan.add_step(
                "secret_scanner",
                {"files": all_scan_files},
                "Escanear TODOS los archivos de código y configuración en busca de secretos "
                "expuestos (API keys, passwords, tokens). Esta es la vulnerabilidad más "
                "crítica porque da acceso directo a sistemas externos."
            )

        # SI hay archivos de dependencias → auditar dependencias
        if ctx.has_requirements or ctx.has_package_json:
            dep_files = [f for f in ctx.file_list if os.path.basename(f) in self.DEPENDENCY_FILES]
            plan.add_step(
                "dependency_audit",
                {"files": dep_files},
                "Se detectaron archivos de dependencias. Auditar versiones contra la base "
                "de datos de vulnerabilidades conocidas (CVEs). Las dependencias inseguras "
                "son un vector de ataque frecuente en la cadena de suministro."
            )

        # SI hay archivos Python/JS/PHP → buscar inyección SQL
        if ctx.has_python_files or ctx.has_js_files:
            plan.add_step(
                "sqli_detector",
                {"files": code_files},
                "Se detectó código fuente en lenguajes que típicamente interactúan con bases "
                "de datos. Analizar en busca de inyección SQL: consultas construidas con "
                "concatenación de strings o f-strings sin parametrización."
            )

        # SI hay archivos HTML/JS o Python (Flask/Django renderizan HTML) → buscar XSS
        if ctx.has_html_files or ctx.has_js_files or ctx.has_python_files:
            web_files = [f for f in ctx.file_list if os.path.splitext(f)[1] in self.WEB_EXTENSIONS]
            plan.add_step(
                "xss_detector",
                {"files": list(dict.fromkeys(web_files + code_files))},
                "Se detectaron archivos web (HTML/JS) o código de servidor que genera HTML. "
                "Analizar en busca de XSS y SSTI: contenido renderizado sin sanitización, "
                "innerHTML, document.write, render_template_string."
            )

        # SI hay archivos de configuración → auditar configuración
        if ctx.has_config_files or ctx.has_env_files:
            plan.add_step(
                "config_auditor",
                {"files": all_scan_files},
                "Se detectaron archivos de configuración. Verificar configuraciones inseguras: "
                "DEBUG habilitado en producción, CORS permisivo, SECRET_KEY débil, "
                "credenciales en texto plano."
            )

        # SI hay logs → analizar logs
        if ctx.log_file_list:
            plan.add_step(
                "log_analyzer",
                {"files": ctx.log_file_list},
                "Se detectaron archivos de logs. Analizar en busca de patrones de ataque: "
                "intentos de fuerza bruta, path traversal, inyección SQL en URLs, "
                "y otros indicadores de compromiso."
            )

        return plan

    def explain_plan(self, plan: ActionPlan) -> str:
        """Genera una explicación legible del plan (chain of thought)."""
        lines = [
            "RAZONAMIENTO DEL AGENTE — Plan de análisis",
            "",
            f"  Proyecto:               {plan.context.target_path}",
            f"  Archivos encontrados:   {plan.context.total_files}",
            f"  Herramientas a ejecutar: {len(plan.steps)}",
            "",
        ]
        for i, step in enumerate(plan.steps, 1):
            lines.append(f"  {i}. [{step['tool']}] {step['reason']}")
        if plan.skipped:
            lines.append(f"  Omitidas por el skill: {', '.join(plan.skipped)}")
        return "\n".join(lines)
