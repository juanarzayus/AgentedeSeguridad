#!/usr/bin/env python3
"""
SecScan Agent — Agente Inteligente de Revisión de Seguridad
============================================================

Punto de entrada principal (CLI).

Este agente analiza repositorios de código y archivos de logs
para detectar vulnerabilidades de seguridad comunes, utilizando
un sistema de Tools (herramientas) y Skills (habilidades).

Uso:
    python main.py --target ./mi_proyecto
    python main.py --target ./mi_proyecto --logs ./logs --format html
    python main.py --target ./mi_proyecto --format pdf --lang en
    python main.py --help

Códigos de salida:
    0  Sin hallazgos
    1  Hallazgos de severidad ALTA, MEDIA o BAJA
    2  Al menos un hallazgo CRÍTICO
    3  Error de uso o de ejecución (argumentos inválidos, directorio inexistente,
       una herramienta falló, PDF no disponible)
"""

import argparse
import os
import sys

from rich import box
from rich.table import Table

from agent.ui import console, print_banner, print_final
from report.generator import FORMATS, PdfUnavailableError
from report.i18n import SUPPORTED_LANGS
from report.insights import build_insights
from skills.security_review import SecurityReviewSkill

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_CRITICAL = 2
EXIT_ERROR = 3

TOOLS_INFO = [
    ("SecretScanner", "Secretos expuestos: API keys, contraseñas, tokens, claves privadas"),
    ("DependencyAudit", "Dependencias con CVE conocidos (requirements.txt, package.json)"),
    ("SQLiDetector", "Inyección SQL (análisis AST en Python, regex en otros lenguajes)"),
    ("XSSDetector", "Cross-Site Scripting y Server-Side Template Injection"),
    ("ConfigAuditor", "Configuración insegura: DEBUG, CORS, SSL, SECRET_KEY"),
    ("LogAnalyzer", "Patrones de ataque en logs: fuerza bruta, traversal, escáneres"),
]


class SecScanArgumentParser(argparse.ArgumentParser):
    """argparse sale con código 2 ante un error de uso; aquí 2 significa 'críticos'."""

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(EXIT_ERROR, f"{self.prog}: error: {message}\n")


def print_tools_info():
    """Imprime herramientas y skills disponibles."""
    tools = Table(title="Herramientas", title_justify="left", title_style="bold",
                  box=box.SIMPLE_HEAD, show_edge=False, header_style="dim")
    tools.add_column("Tool", style="bold cyan", no_wrap=True)
    tools.add_column("Detecta")
    for name, desc in TOOLS_INFO:
        tools.add_row(name, desc)

    skills = Table(title="Skills", title_justify="left", title_style="bold",
                   box=box.SIMPLE_HEAD, show_edge=False, header_style="dim")
    skills.add_column("Skill", style="bold cyan", no_wrap=True)
    skills.add_column("Descripción")
    skills.add_column("Tools", style="dim")
    for key, info in SecurityReviewSkill.SKILL_DEFINITIONS.items():
        skills.add_row(key, info["name"], ", ".join(info["tools_used"]))

    console.print()
    console.print(tools)
    console.print()
    console.print(skills)
    console.print()


def error(message: str) -> int:
    console.print(f"[bold red]error[/] {message}", highlight=False)
    return EXIT_ERROR


def main():
    """Punto de entrada principal del agente."""
    parser = SecScanArgumentParser(
        description="SecScan Agent — Agente Inteligente de Revisión de Seguridad",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python main.py --target ./test_project
  python main.py --target ./test_project --logs ./test_project/logs --format html
  python main.py --target ./test_project --format pdf --lang en
  python main.py --target ./test_project --skill quick_scan
  python main.py --list-tools

Códigos de salida: 0 = sin hallazgos, 1 = hallazgos, 2 = hallazgos críticos, 3 = error
        """,
    )
    parser.add_argument("--target", "-t", help="Directorio del proyecto a analizar")
    parser.add_argument("--logs", "-l", default=None, help="Directorio de logs a analizar (opcional)")
    parser.add_argument("--format", "-f", choices=FORMATS, default="text",
                        help="Formato del reporte (default: text)")
    parser.add_argument("--lang", choices=SUPPORTED_LANGS, default="es",
                        help="Idioma del reporte (default: es)")
    parser.add_argument("--skill", "-s", choices=list(SecurityReviewSkill.SKILL_DEFINITIONS),
                        default="full_security_review",
                        help="Skill a ejecutar (default: full_security_review)")
    parser.add_argument("--output", "-o", default="reports",
                        help="Directorio de salida para reportes (default: reports)")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Modo silencioso: solo el resultado final")
    parser.add_argument("--list-tools", action="store_true",
                        help="Listar herramientas y skills disponibles")

    args = parser.parse_args()

    if not args.quiet or args.list_tools:
        print_banner()

    if args.list_tools:
        print_tools_info()
        return EXIT_CLEAN

    if not args.target:
        error("debe especificar un directorio con --target")
        console.print("  [dim]Demo:[/] python main.py --target ./test_project --logs ./test_project/logs --format html")
        return EXIT_ERROR

    if not os.path.isdir(args.target):
        return error(f"el directorio '{args.target}' no existe")

    if args.logs and not os.path.isdir(args.logs):
        console.print(f"[yellow]aviso[/] el directorio de logs '{args.logs}' no existe; se omite el análisis de logs")
        args.logs = None

    skill = SecurityReviewSkill(verbose=not args.quiet)
    try:
        results = skill.execute(
            skill_name=args.skill,
            target_path=args.target,
            logs_path=args.logs,
            output_format=args.format,
            output_dir=args.output,
            lang=args.lang,
        )
    except PdfUnavailableError as e:
        return error(str(e))

    if "error" in results:
        return error(results["error"])

    print_final(results, build_insights(results, args.lang))

    tool_errors = results.get("tool_errors", 0)
    if tool_errors:
        console.print(f"[bold red]error[/] {tool_errors} herramienta(s) fallaron: el análisis está incompleto")

    # Código de salida: un análisis incompleto no puede reportarse como "limpio"
    total = results.get("total_findings", 0)
    critical = results.get("severity_counts", {}).get("CRITICA", 0)
    if tool_errors:
        return EXIT_ERROR
    if critical > 0:
        return EXIT_CRITICAL
    if total > 0:
        return EXIT_FINDINGS
    return EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
