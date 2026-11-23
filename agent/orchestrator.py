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

from agent.findings import SEVERITY_ORDER, deduplicate, is_suppressed
from agent.planner import Planner, ActionPlan
from agent.ui import NullReporter, RichReporter
from agent.tool_registry import ToolRegistry, ToolDefinition
from tools.secret_scanner import scan_secrets
from tools.dependency_audit import audit_dependencies
from tools.sqli_detector import detect_sqli
from tools.xss_detector import detect_xss
from tools.log_analyzer import analyze_logs
from tools.config_auditor import audit_config


class SecScanOrchestrator:
    """
    Orquestador principal del agente de seguridad.

    Coordina el flujo completo:
    Planner (razonamiento) → Tools (ejecución) → Report (presentación)
    """

    def __init__(self, verbose: bool = True, reporter=None):
        """
        Args:
            verbose: Mostrar el progreso en la terminal (ignorado si se pasa `reporter`).
            reporter: Receptor de eventos de progreso (ver agent/ui.py). Permite que
                      otra interfaz (p. ej. una web) muestre la ejecución en vivo.
        """
        self.verbose = verbose
        self.ui = reporter or (RichReporter() if verbose else NullReporter())
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

        # ── FASE 1: OBSERVAR — Analizar el contexto ──
        self.ui.phase(1, "observe")
        try:
            context = self.planner.analyze_context(target_path, logs_path)
        except FileNotFoundError as e:
            return {"error": str(e), "findings": []}
        self.ui.context(context)

        # ── FASE 2: RAZONAR — Crear plan de acción ──
        self.ui.phase(2, "reason")
        plan = self.planner.create_plan(context, allowed_tools=allowed_tools)
        self.ui.plan(plan, self.registry.tool_count)

        # ── FASE 3: ACTUAR — Ejecutar herramientas ──
        self.ui.phase(3, "act")
        total_steps = len(plan.steps)
        for i, step in enumerate(plan.steps, 1):
            tool_name = step["tool"]
            step_start = time.time()
            with self.ui.step_start(i, total_steps, tool_name):
                try:
                    results = self.registry.execute_tool(tool_name, **step["params"]) or []
                    self.findings.extend(results)
                    entry = {"step": i, "tool": tool_name, "status": "success",
                             "findings_count": len(results)}
                except Exception as e:  # una herramienta rota no detiene al agente
                    entry = {"step": i, "tool": tool_name, "status": "error",
                             "error": str(e), "findings_count": 0}
            entry["time_seconds"] = round(time.time() - step_start, 2)
            self.execution_log.append(entry)
            self.ui.step_end(i, total_steps, entry)

        # ── FASE 4: REPORTAR — Compilar resultados ──
        self.ui.phase(4, "report")
        total_time = time.time() - start_time

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

        results = {
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
        self.ui.summary(results)
        return results
