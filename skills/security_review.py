"""
SecurityReview Skill — Skill de alto nivel para revisión de seguridad.

Los Skills son capacidades de alto nivel del agente que combinan
múltiples tools para realizar tareas complejas.

Este skill implementa tres modos de operación:
1. full_security_review — Análisis completo con todas las herramientas
2. quick_scan — Escaneo rápido (solo secretos + SQLi)
3. dependency_check — Solo auditoría de dependencias
"""

from agent.orchestrator import SecScanOrchestrator
from report.generator import ReportGenerator


class SecurityReviewSkill:
    """
    Skill de revisión de seguridad del agente.

    Encapsula la lógica de alto nivel para ejecutar diferentes tipos
    de análisis de seguridad. El agente selecciona el skill apropiado
    basándose en el objetivo del usuario.
    """

    SKILL_DEFINITIONS = {
        "full_security_review": {
            "name": "Revisión de Seguridad Completa",
            "description": "Ejecuta TODAS las herramientas de seguridad disponibles, "
                           "analiza todos los archivos del proyecto y logs, y genera "
                           "un reporte priorizado completo.",
            "tools_used": [
                "secret_scanner", "dependency_audit", "sqli_detector",
                "xss_detector", "log_analyzer", "config_auditor",
            ],
        },
        "quick_scan": {
            "name": "Escaneo Rápido",
            "description": "Escaneo enfocado en las vulnerabilidades más críticas: "
                           "secretos expuestos e inyección SQL.",
            "tools_used": ["secret_scanner", "sqli_detector"],
        },
        "dependency_check": {
            "name": "Auditoría de Dependencias",
            "description": "Solo revisa las dependencias del proyecto contra la base "
                           "de datos de vulnerabilidades conocidas.",
            "tools_used": ["dependency_audit"],
        },
    }

    def __init__(self, verbose: bool = True):
        self.verbose = verbose

    def list_skills(self) -> dict:
        """Lista los skills disponibles con sus descripciones."""
        return self.SKILL_DEFINITIONS

    def execute(
        self,
        skill_name: str,
        target_path: str,
        logs_path: str | None = None,
        output_format: str = "text",
        output_dir: str = "reports",
    ) -> dict:
        """
        Ejecuta un skill de seguridad.

        Args:
            skill_name: Nombre del skill a ejecutar.
            target_path: Ruta al proyecto a analizar.
            logs_path: Ruta opcional a logs.
            output_format: Formato del reporte (text, html, json).
            output_dir: Directorio de salida para reportes.

        Returns:
            Resultados del análisis.
        """
        if skill_name not in self.SKILL_DEFINITIONS:
            raise ValueError(
                f"Skill '{skill_name}' no encontrado. "
                f"Disponibles: {list(self.SKILL_DEFINITIONS.keys())}"
            )

        skill_info = self.SKILL_DEFINITIONS[skill_name]

        if self.verbose:
            print(f"\n{'═' * 55}")
            print(f"  🎯 Ejecutando Skill: {skill_info['name']}")
            print(f"  📝 {skill_info['description'][:80]}...")
            print(f"  🔧 Tools: {', '.join(skill_info['tools_used'])}")
            print(f"{'═' * 55}")

        # Crear y ejecutar el orquestador
        orchestrator = SecScanOrchestrator(verbose=self.verbose)
        results = orchestrator.run(target_path, logs_path)

        # Generar reporte
        generator = ReportGenerator()
        report_path = generator.generate(
            results,
            format=output_format,
            output_dir=output_dir,
        )

        results["report_path"] = report_path
        results["skill_used"] = skill_name

        if self.verbose:
            print(f"\n  📄 Reporte generado: {report_path}")

        return results
