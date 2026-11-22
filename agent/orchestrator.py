"""
Orchestrator — Orquestador principal del agente SecScan.

Este módulo implementa el bucle principal del agente:
1. Recibe el objetivo del usuario
2. Usa el Planner para analizar el contexto y crear un plan
3. Ejecuta las herramientas del plan usando el ToolRegistry
4. Recopila los resultados y los entrega al generador de reportes

El patrón es: OBSERVAR → RAZONAR → ACTUAR → REPORTAR
"""

import os
import time
from colorama import Fore, Style, init

from agent.findings import SEVERITY_ORDER, deduplicate, is_suppressed
from agent.planner import Planner, ActionPlan
from agent.tool_registry import ToolRegistry, ToolDefinition
from tools.secret_scanner import scan_secrets
from tools.dependency_audit import audit_dependencies
from tools.sqli_detector import detect_sqli
from tools.xss_detector import detect_xss
from tools.log_analyzer import analyze_logs
from tools.config_auditor import audit_config

# Inicializar colorama para colores en terminal
init(autoreset=True)


class SecScanOrchestrator:
    """
    Orquestador principal del agente de seguridad.

    Coordina el flujo completo:
    Planner (razonamiento) → Tools (ejecución) → Report (presentación)
    """

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.registry = ToolRegistry()
        self.planner = Planner()
        self.findings: list[dict] = []
        self.execution_log: list[dict] = []

        # Registrar todas las herramientas
        self._register_tools()

    def _register_tools(self):
        """Registra todas las herramientas disponibles en el agente."""
        tools = [
            ToolDefinition(
                name="secret_scanner",
                description="Escanea código fuente en busca de secretos expuestos "
                            "(API keys, passwords, tokens, claves privadas)",
                category="vulnerability_detection",
                execute=scan_secrets,
                parameters={"files": "Lista de archivos a escanear"},
            ),
            ToolDefinition(
                name="dependency_audit",
                description="Audita dependencias del proyecto contra base de datos "
                            "de vulnerabilidades conocidas (CVEs)",
                category="supply_chain",
                execute=audit_dependencies,
                parameters={"files": "Lista de archivos de dependencias"},
            ),
            ToolDefinition(
                name="sqli_detector",
                description="Detecta patrones de inyección SQL en el código fuente: "
                            "concatenación de strings, f-strings, format() en queries",
                category="vulnerability_detection",
                execute=detect_sqli,
                parameters={"files": "Lista de archivos de código fuente"},
            ),
            ToolDefinition(
                name="xss_detector",
                description="Detecta vulnerabilidades Cross-Site Scripting: innerHTML, "
                            "document.write, templates sin escape",
                category="vulnerability_detection",
                execute=detect_xss,
                parameters={"files": "Lista de archivos web/código"},
            ),
            ToolDefinition(
                name="log_analyzer",
                description="Analiza logs de acceso en busca de patrones de ataque: "
                            "fuerza bruta, path traversal, SQLi en URLs",
                category="threat_detection",
                execute=analyze_logs,
                parameters={"files": "Lista de archivos de logs"},
            ),
            ToolDefinition(
                name="config_auditor",
                description="Audita configuraciones de seguridad: DEBUG, CORS, "
                            "SECRET_KEY, SSL, credenciales en config",
                category="configuration",
                execute=audit_config,
                parameters={"files": "Lista de archivos de configuración"},
            ),
        ]

        for tool in tools:
            self.registry.register(tool)

    def _log(self, message: str, color: str = Fore.WHITE):
        """Imprime un mensaje si el modo verbose está activo."""
        if self.verbose:
            print(f"{color}{message}{Style.RESET_ALL}")

    def _log_step(self, step_num: int, tool_name: str, status: str, details: str = ""):
        """Registra la ejecución de un paso del plan."""
        icons = {
            "INICIANDO": "🔄",
            "COMPLETADO": "✅",
            "ERROR": "❌",
            "SIN_HALLAZGOS": "✨",
        }
        icon = icons.get(status, "❓")
        self._log(f"\n  {icon} Paso {step_num}: [{tool_name}] — {status}")
        if details:
            self._log(f"     {details}", Fore.CYAN)

    @staticmethod
    def _apply_suppressions(findings: list[dict]) -> tuple[list[dict], int]:
        """Descarta hallazgos cuya línea tiene `# secscan: ignore` o `# nosec`."""
        cache: dict[str, list[str]] = {}
        kept, suppressed = [], 0
        for f in findings:
            path, line = f.get("file", ""), f.get("line", 0)
            if line > 0 and os.path.isfile(path):
                if path not in cache:
                    try:
                        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                            cache[path] = fh.read().splitlines()
                    except OSError:
                        cache[path] = []
                lines = cache[path]
                if line <= len(lines) and is_suppressed(lines[line - 1]):
                    suppressed += 1
                    continue
            kept.append(f)
        return kept, suppressed

    def run(self, target_path: str, logs_path: str | None = None,
            allowed_tools: list[str] | None = None) -> dict:
        """
        Ejecuta el agente de seguridad sobre un directorio objetivo.

        Este es el bucle principal del agente, siguiendo el patrón:
        OBSERVAR → RAZONAR → ACTUAR → REPORTAR

        Args:
            target_path: Ruta al directorio del proyecto a analizar.
            logs_path: Ruta opcional al directorio de logs.
            allowed_tools: Herramientas que el skill permite ejecutar (None = todas).

        Returns:
            Diccionario con todos los hallazgos y metadata del análisis.
        """
        start_time = time.time()
        self.findings = []
        self.execution_log = []

        # ═══════════════════════════════════════
        # FASE 1: OBSERVAR — Analizar el contexto
        # ═══════════════════════════════════════
        self._log("\n" + "═" * 55, Fore.YELLOW)
        self._log("  🔍 FASE 1: OBSERVAR — Analizando el proyecto...", Fore.YELLOW)
        self._log("═" * 55, Fore.YELLOW)

        try:
            context = self.planner.analyze_context(target_path, logs_path)
        except FileNotFoundError as e:
            self._log(f"\n  ❌ Error: {e}", Fore.RED)
            return {"error": str(e), "findings": []}

        self._log(f"\n  📂 Directorio: {target_path}", Fore.CYAN)
        self._log(f"  📄 Archivos encontrados: {context.total_files}", Fore.CYAN)
        self._log(f"  🐍 Archivos Python: {'Sí' if context.has_python_files else 'No'}", Fore.CYAN)
        self._log(f"  📦 Dependencias: {'Sí' if context.has_requirements else 'No'}", Fore.CYAN)
        self._log(f"  ⚙️  Configuración: {'Sí' if context.has_config_files else 'No'}", Fore.CYAN)
        self._log(f"  📋 Logs: {'Sí' if context.has_log_files else 'No'}", Fore.CYAN)
        if context.ignored_files:
            self._log(f"  🙈 Ignorados por .secscanignore: {context.ignored_files}", Fore.CYAN)

        # ═══════════════════════════════════════
        # FASE 2: RAZONAR — Crear plan de acción
        # ═══════════════════════════════════════
        self._log("\n" + "═" * 55, Fore.YELLOW)
        self._log("  🧠 FASE 2: RAZONAR — Creando plan de acción...", Fore.YELLOW)
        self._log("═" * 55, Fore.YELLOW)

        plan = self.planner.create_plan(context, allowed_tools=allowed_tools)

        self._log(f"\n  📋 Plan generado: {len(plan.steps)} herramientas a ejecutar", Fore.GREEN)
        for i, step in enumerate(plan.steps, 1):
            self._log(f"  {i}. {step['tool']}: {step['reason'][:80]}...", Fore.WHITE)

        self._log(f"\n  🔧 Herramientas disponibles: {self.registry.tool_count}", Fore.CYAN)
        self._log(f"  🎯 Herramientas seleccionadas: {len(plan.steps)}", Fore.CYAN)
        if plan.skipped:
            self._log(f"  ⏭️  Omitidas por el skill: {', '.join(plan.skipped)}", Fore.CYAN)

        # ═══════════════════════════════════════
        # FASE 3: ACTUAR — Ejecutar herramientas
        # ═══════════════════════════════════════
        self._log("\n" + "═" * 55, Fore.YELLOW)
        self._log("  ⚡ FASE 3: ACTUAR — Ejecutando herramientas...", Fore.YELLOW)
        self._log("═" * 55, Fore.YELLOW)

        for i, step in enumerate(plan.steps, 1):
            tool_name = step["tool"]
            params = step["params"]

            self._log_step(i, tool_name, "INICIANDO")

            step_start = time.time()
            try:
                results = self.registry.execute_tool(tool_name, **params)
                step_time = time.time() - step_start

                if results:
                    self.findings.extend(results)
                    self._log_step(i, tool_name, "COMPLETADO",
                                   f"{len(results)} hallazgos en {step_time:.2f}s")
                else:
                    self._log_step(i, tool_name, "SIN_HALLAZGOS",
                                   f"Ninguna vulnerabilidad detectada ({step_time:.2f}s)")

                self.execution_log.append({
                    "step": i,
                    "tool": tool_name,
                    "status": "success",
                    "findings_count": len(results),
                    "time_seconds": round(step_time, 2),
                })

            except Exception as e:
                step_time = time.time() - step_start
                self._log_step(i, tool_name, "ERROR", str(e))
                self.execution_log.append({
                    "step": i,
                    "tool": tool_name,
                    "status": "error",
                    "error": str(e),
                    "time_seconds": round(step_time, 2),
                })

        # ═══════════════════════════════════════
        # FASE 4: REPORTAR — Compilar resultados
        # ═══════════════════════════════════════
        total_time = time.time() - start_time

        self._log("\n" + "═" * 55, Fore.YELLOW)
        self._log("  📊 FASE 4: REPORTAR — Compilando resultados...", Fore.YELLOW)
        self._log("═" * 55, Fore.YELLOW)

        # Limpiar: supresiones en línea y duplicados (misma línea + mismo CWE, aunque
        # lo hayan detectado herramientas distintas)
        raw_count = len(self.findings)
        self.findings, suppressed_count = self._apply_suppressions(self.findings)
        self.findings = deduplicate(self.findings)
        merged_count = raw_count - suppressed_count - len(self.findings)

        # Priorizar hallazgos por severidad (y luego por ubicación, para un orden estable)
        self.findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.get("severity", "BAJA"), 4),
                                          f.get("file", ""), f.get("line", 0)))

        # Conteo por severidad
        severity_counts = {}
        for f in self.findings:
            sev = f.get("severity", "BAJA")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Conteo por herramienta
        tool_counts = {}
        for f in self.findings:
            tool = f.get("tool", "Unknown")
            tool_counts[tool] = tool_counts.get(tool, 0) + 1

        self._log(f"\n  🔍 Total de hallazgos: {len(self.findings)}", Fore.GREEN)
        if merged_count or suppressed_count:
            self._log(f"     ({merged_count} duplicados fusionados, {suppressed_count} suprimidos)", Fore.CYAN)
        for sev in ["CRITICA", "ALTA", "MEDIA", "BAJA"]:
            count = severity_counts.get(sev, 0)
            color_map = {"CRITICA": Fore.RED, "ALTA": Fore.YELLOW,
                         "MEDIA": Fore.CYAN, "BAJA": Fore.BLUE}
            if count > 0:
                self._log(f"    {'🔴' if sev == 'CRITICA' else '🟠' if sev == 'ALTA' else '🟡' if sev == 'MEDIA' else '🔵'} "
                          f"{sev}: {count}", color_map.get(sev, Fore.WHITE))

        self._log(f"\n  ⏱️  Tiempo total: {total_time:.2f} segundos", Fore.CYAN)

        return {
            "target": target_path,
            "logs_path": logs_path,
            "total_findings": len(self.findings),
            "severity_counts": severity_counts,
            "tool_counts": tool_counts,
            "findings": self.findings,
            "execution_log": self.execution_log,
            "tool_errors": sum(1 for e in self.execution_log if e["status"] == "error"),
            "suppressed_count": suppressed_count,
            "merged_duplicates": merged_count,
            "plan": plan.to_dict(),
            "context": {
                "total_files": context.total_files,
                "has_python": context.has_python_files,
                "has_js": context.has_js_files,
                "has_html": context.has_html_files,
                "has_config": context.has_config_files,
                "has_logs": context.has_log_files,
                "has_dependencies": context.has_requirements,
                "ignored_files": context.ignored_files,
            },
            "total_time_seconds": round(total_time, 2),
        }
