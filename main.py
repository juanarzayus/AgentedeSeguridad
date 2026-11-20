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
    python main.py --target ./mi_proyecto --format json
    python main.py --help
"""

import argparse
import sys
import os

from colorama import Fore, Style, init

from skills.security_review import SecurityReviewSkill

# Inicializar colores
init(autoreset=True)


def print_banner():
    """Imprime el banner del agente."""
    banner = f"""{Fore.CYAN}
    ╔═══════════════════════════════════════════════════════╗
    ║                                                       ║
    ║   🛡️  SecScan Agent v1.0                              ║
    ║   Agente Inteligente de Revisión de Seguridad          ║
    ║                                                       ║
    ║   Tools:  SecretScanner | DependencyAudit | SQLi      ║
    ║           XSSDetector | LogAnalyzer | ConfigAuditor    ║
    ║                                                       ║
    ║   Skills: full_security_review | quick_scan            ║
    ║           dependency_check                             ║
    ║                                                       ║
    ╚═══════════════════════════════════════════════════════╝
    {Style.RESET_ALL}"""
    print(banner)


def print_tools_info():
    """Imprime información sobre las herramientas disponibles."""
    print(f"\n{Fore.CYAN}  🔧 Herramientas (Tools) del Agente:{Style.RESET_ALL}")
    tools = [
        ("🔑 SecretScanner", "Detecta secretos expuestos (API keys, passwords, tokens)"),
        ("📦 DependencyAudit", "Audita dependencias contra CVEs conocidos"),
        ("💉 SQLiDetector", "Detecta patrones de inyección SQL"),
        ("🌐 XSSDetector", "Detecta vulnerabilidades Cross-Site Scripting"),
        ("📋 LogAnalyzer", "Analiza logs en busca de patrones de ataque"),
        ("⚙️  ConfigAuditor", "Audita configuraciones de seguridad"),
    ]
    for name, desc in tools:
        print(f"    {name:25s} — {desc}")

    print(f"\n{Fore.CYAN}  🎯 Skills del Agente:{Style.RESET_ALL}")
    skills = [
        ("full_security_review", "Revisión completa con todas las herramientas"),
        ("quick_scan", "Escaneo rápido (secretos + SQLi)"),
        ("dependency_check", "Solo auditoría de dependencias"),
    ]
    for name, desc in skills:
        print(f"    {name:25s} — {desc}")
    print()


def main():
    """Punto de entrada principal del agente."""
    parser = argparse.ArgumentParser(
        description="🛡️ SecScan Agent — Agente Inteligente de Revisión de Seguridad",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python main.py --target ./test_project
  python main.py --target ./test_project --logs ./test_project/logs
  python main.py --target ./test_project --format html
  python main.py --target ./test_project --skill quick_scan
  python main.py --list-tools
        """,
    )

    parser.add_argument(
        "--target", "-t",
        help="Directorio del proyecto a analizar",
    )
    parser.add_argument(
        "--logs", "-l",
        help="Directorio de logs a analizar (opcional)",
        default=None,
    )
    parser.add_argument(
        "--format", "-f",
        choices=["text", "html", "json"],
        default="text",
        help="Formato del reporte (default: text)",
    )
    parser.add_argument(
        "--skill", "-s",
        choices=["full_security_review", "quick_scan", "dependency_check"],
        default="full_security_review",
        help="Skill a ejecutar (default: full_security_review)",
    )
    parser.add_argument(
        "--output", "-o",
        default="reports",
        help="Directorio de salida para reportes (default: reports)",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Modo silencioso (menos output en terminal)",
    )
    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="Listar herramientas y skills disponibles",
    )

    args = parser.parse_args()

    # Mostrar banner
    print_banner()

    # Si pidieron listar herramientas
    if args.list_tools:
        print_tools_info()
        return 0

    # Validar que se proporcionó un target
    if not args.target:
        print(f"{Fore.RED}  ❌ Error: Debe especificar un directorio con --target{Style.RESET_ALL}")
        print(f"  Uso: python main.py --target ./mi_proyecto")
        print(f"  Demo: python main.py --target ./test_project --format html")
        return 1

    # Validar que el directorio existe
    if not os.path.isdir(args.target):
        print(f"{Fore.RED}  ❌ Error: El directorio '{args.target}' no existe{Style.RESET_ALL}")
        return 1

    # Validar directorio de logs si se proporcionó
    if args.logs and not os.path.isdir(args.logs):
        print(f"{Fore.YELLOW}  ⚠️  Advertencia: El directorio de logs '{args.logs}' no existe{Style.RESET_ALL}")
        args.logs = None

    # Ejecutar el skill seleccionado
    skill = SecurityReviewSkill(verbose=not args.quiet)
    results = skill.execute(
        skill_name=args.skill,
        target_path=args.target,
        logs_path=args.logs,
        output_format=args.format,
        output_dir=args.output,
    )

    # Resumen final
    total = results.get("total_findings", 0)
    critical = results.get("severity_counts", {}).get("CRITICA", 0)

    print(f"\n{'═' * 55}")
    if total == 0:
        print(f"  {Fore.GREEN}✅ ¡No se encontraron vulnerabilidades!{Style.RESET_ALL}")
    elif critical > 0:
        print(f"  {Fore.RED}🚨 Se encontraron {critical} vulnerabilidades CRÍTICAS{Style.RESET_ALL}")
        print(f"  {Fore.RED}   Acción inmediata requerida.{Style.RESET_ALL}")
    else:
        print(f"  {Fore.YELLOW}⚠️  Se encontraron {total} hallazgos de seguridad{Style.RESET_ALL}")

    print(f"  📄 Reporte: {results.get('report_path', 'N/A')}")
    print(f"{'═' * 55}\n")

    # Código de salida basado en severidad
    if critical > 0:
        return 2  # Vulnerabilidades críticas
    elif total > 0:
        return 1  # Vulnerabilidades encontradas
    return 0


if __name__ == "__main__":
    sys.exit(main())
