"""
Planner — Motor de razonamiento y planificación del agente.

El Planner analiza el objetivo del usuario (escanear un proyecto),
examina el contexto (qué archivos existen, qué tipo de proyecto es),
y decide qué herramientas ejecutar y en qué orden.

Utiliza un sistema de reglas + heurísticas para simular razonamiento,
similar a cómo un LLM planificaría una secuencia de acciones.
"""

import os
from pathlib import Path
from dataclasses import dataclass, field


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


@dataclass
class ActionPlan:
    """Plan de acción generado por el Planner."""
    steps: list[dict] = field(default_factory=list)
    reasoning: list[str] = field(default_factory=list)
    context: ScanContext | None = None

    def add_step(self, tool_name: str, params: dict, reason: str) -> None:
        """Agrega un paso al plan con su justificación."""
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

        # Recorrer archivos del proyecto
        for root, dirs, files in os.walk(target_path):
            # Ignorar directorios irrelevantes
            dirs[:] = [d for d in dirs if d not in {
                ".git", "__pycache__", "node_modules", ".venv", "venv", ".tox",
            }]
            for f in files:
                filepath = os.path.join(root, f)
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
                elif ext == ".log":
                    ctx.has_log_files = True

                # Detectar archivos especiales
                if f in {"requirements.txt", "Pipfile", "pyproject.toml", "package.json"}:
                    ctx.has_requirements = True
                    if f == "package.json":
                        ctx.has_package_json = True
                if f.lower() in {n.lower() for n in self.CONFIG_FILES}:
                    ctx.has_config_files = True
                if f.startswith(".env"):
                    ctx.has_env_files = True

        # Verificar directorio de logs
        if logs_path and os.path.exists(logs_path):
            for f in os.listdir(logs_path):
                if f.endswith(".log") or f.endswith(".txt"):
                    ctx.has_log_files = True
                    ctx.file_list.append(os.path.join(logs_path, f))

        return ctx

    def create_plan(self, ctx: ScanContext) -> ActionPlan:
        """
        PASO 2 y 3: RAZONAR + PLANIFICAR
        
        Basándose en el contexto observado, decide qué herramientas ejecutar
        y en qué orden. Prioriza por impacto de seguridad.
        """
        plan = ActionPlan(context=ctx)

        # --- Razonamiento del agente ---

        # SIEMPRE: Escanear secretos (prioridad máxima)
        # Razonamiento: Los secretos expuestos son la vulnerabilidad más crítica
        # porque dan acceso directo a sistemas.
        code_files = [f for f in ctx.file_list if os.path.splitext(f)[1] in self.CODE_EXTENSIONS]
        config_files = [f for f in ctx.file_list if os.path.basename(f).lower() in {n.lower() for n in self.CONFIG_FILES}]
        env_files = [f for f in ctx.file_list if os.path.basename(f).startswith(".env")]
        all_scan_files = list(set(code_files + config_files + env_files))

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

        # SI hay archivos HTML/JS → buscar XSS
        if ctx.has_html_files or ctx.has_js_files:
            web_files = [f for f in ctx.file_list if os.path.splitext(f)[1] in self.WEB_EXTENSIONS]
            plan.add_step(
                "xss_detector",
                {"files": web_files + code_files},
                "Se detectaron archivos web (HTML/JS). Analizar en busca de vulnerabilidades "
                "XSS: contenido renderizado sin sanitización, innerHTML, document.write."
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
        if ctx.has_log_files and ctx.logs_path:
            log_files = [f for f in ctx.file_list if f.endswith(".log") or f.endswith(".txt")]
            # Filtrar solo los que están en el directorio de logs
            log_dir_files = [f for f in log_files if ctx.logs_path in f]
            if log_dir_files:
                plan.add_step(
                    "log_analyzer",
                    {"files": log_dir_files},
                    "Se detectaron archivos de logs. Analizar en busca de patrones de ataque: "
                    "intentos de fuerza bruta, path traversal, inyección SQL en URLs, "
                    "y otros indicadores de compromiso."
                )

        return plan

    def explain_plan(self, plan: ActionPlan) -> str:
        """Genera una explicación legible del plan (chain of thought)."""
        lines = [
            "═══════════════════════════════════════════════════",
            "  🧠 RAZONAMIENTO DEL AGENTE — Plan de Análisis",
            "═══════════════════════════════════════════════════",
            "",
            f"  📂 Proyecto: {plan.context.target_path}",
            f"  📄 Archivos encontrados: {plan.context.total_files}",
            f"  🔧 Herramientas a ejecutar: {len(plan.steps)}",
            "",
        ]

        for i, step in enumerate(plan.steps, 1):
            lines.append(f"  Paso {i}: [{step['tool']}]")
            lines.append(f"    → {step['reason'][:100]}...")
            lines.append("")

        lines.append("═══════════════════════════════════════════════════")
        return "\n".join(lines)
