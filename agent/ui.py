"""
UI — Presentación del progreso del agente.

El orquestador no imprime nada: emite eventos a un `Reporter`. Así la misma
ejecución puede mostrarse en la terminal (RichReporter), no mostrarse
(NullReporter) o, más adelante, transmitirse a una interfaz web.

Eventos:
    phase(number, key)                   — inicia una fase del ciclo del agente
    context(ctx)                         — resultado de OBSERVAR
    plan(plan, available_tools)          — resultado de RAZONAR
    step_start(index, total, tool)       — una herramienta empieza
    step_end(index, total, entry)        — una herramienta termina (entry = execution_log)
    summary(results)                     — resultado de REPORTAR
"""

from __future__ import annotations

from contextlib import contextmanager

from rich.console import Console
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

VERSION = "1.1.0"

SEVERITY_STYLE = {
    "CRITICA": "bold red",
    "ALTA": "bold dark_orange",
    "MEDIA": "yellow",
    "BAJA": "grey58",
}
SEVERITY_LABEL = {"CRITICA": "CRIT", "ALTA": "ALTA", "MEDIA": "MEDIA", "BAJA": "BAJA"}

PHASES = {
    "observe": ("Observar", "análisis del proyecto"),
    "reason": ("Razonar", "plan de acción"),
    "act": ("Actuar", "ejecución de herramientas"),
    "report": ("Reportar", "consolidación de resultados"),
}

console = Console(highlight=False)


def severity_text(severity: str) -> Text:
    return Text(f" {SEVERITY_LABEL.get(severity, severity):<5} ", style=f"reverse {SEVERITY_STYLE.get(severity, '')}")


class NullReporter:
    """No muestra nada (modo --quiet, tests, uso como librería)."""

    def phase(self, number, key): pass
    def context(self, ctx): pass
    def plan(self, plan, available_tools): pass
    def step_end(self, index, total, entry): pass
    def summary(self, results): pass

    @contextmanager
    def step_start(self, index, total, tool):
        yield


class RichReporter(NullReporter):
    """Salida de terminal con rich: fases, plan, progreso y resumen."""

    def __init__(self, out: Console | None = None):
        self.out = out or console

    def phase(self, number, key):
        title, subtitle = PHASES[key]
        self.out.print()
        self.out.rule(f"[bold cyan]{number}/4  {title}[/]  [dim]{subtitle}[/]", align="left", style="grey30")

    def context(self, ctx):
        grid = Table.grid(padding=(0, 3))
        grid.add_column(style="dim")
        grid.add_column()
        yes_no = lambda v: "[green]sí[/]" if v else "[dim]no[/]"
        grid.add_row("Directorio", ctx.target_path)
        grid.add_row("Archivos", str(ctx.total_files))
        grid.add_row("Python / JS / HTML", f"{yes_no(ctx.has_python_files)} / {yes_no(ctx.has_js_files)} / {yes_no(ctx.has_html_files)}")
        grid.add_row("Dependencias", yes_no(ctx.has_requirements))
        grid.add_row("Configuración", yes_no(ctx.has_config_files or ctx.has_env_files))
        grid.add_row("Logs", yes_no(ctx.has_log_files))
        if ctx.ignored_files:
            grid.add_row("Ignorados", f"{ctx.ignored_files} [dim](.secscanignore)[/]")
        self.out.print(Padding(grid, (1, 2, 0, 2)))

    def plan(self, plan, available_tools):
        table = Table(box=box.SIMPLE_HEAD, show_edge=False, pad_edge=False, header_style="dim")
        table.add_column("#", justify="right", style="dim", width=2)
        table.add_column("Herramienta", style="bold", no_wrap=True)
        table.add_column("Razonamiento", style="grey70", overflow="fold")
        for step in plan.steps:
            first_sentence = step["reason"].split(". ")[0].rstrip(".") + "."
            table.add_row(str(step["order"]), step["tool"], first_sentence)
        self.out.print(Padding(table, (1, 2, 0, 2)))
        note = f"{len(plan.steps)} de {available_tools} herramientas seleccionadas"
        if plan.skipped:
            note += f" · omitidas por el skill: {', '.join(plan.skipped)}"
        self.out.print(Padding(f"[dim]{note}[/]", (0, 2)))

    @contextmanager
    def step_start(self, index, total, tool):
        with self.out.status(f"[cyan]{tool}[/] [dim]({index}/{total})[/]", spinner="dots"):
            yield

    def step_end(self, index, total, entry):
        tool = entry["tool"]
        secs = f"{entry['time_seconds']:.2f}s"
        if entry["status"] == "error":
            mark, detail = "[bold red]✗[/]", f"[red]{entry.get('error', 'error')}[/]"
        elif entry["findings_count"]:
            mark, detail = "[green]✓[/]", f"{entry['findings_count']} hallazgos"
        else:
            mark, detail = "[green]✓[/]", "[dim]sin hallazgos[/]"
        self.out.print(f"  {mark} [bold]{tool:<18}[/] {detail:<24} [dim]{secs}[/]")

    def summary(self, results):
        counts = results.get("severity_counts", {})
        total = results.get("total_findings", 0)
        width = 28
        table = Table.grid(padding=(0, 2))
        table.add_column()
        table.add_column(justify="right")
        table.add_column()
        for sev in ("CRITICA", "ALTA", "MEDIA", "BAJA"):
            n = counts.get(sev, 0)
            bar = "█" * (round(width * n / total) if total else 0)
            table.add_row(severity_text(sev), f"[bold]{n}[/]", Text(bar, style=SEVERITY_STYLE[sev]))
        self.out.print(Padding(table, (1, 2, 0, 2)))
        extra = []
        if results.get("merged_duplicates"):
            extra.append(f"{results['merged_duplicates']} duplicados fusionados")
        if results.get("suppressed_count"):
            extra.append(f"{results['suppressed_count']} suprimidos")
        extra.append(f"{results.get('total_time_seconds', 0):.2f}s")
        self.out.print(Padding(f"[bold]{total}[/] hallazgos [dim]· {' · '.join(extra)}[/]", (1, 2, 0, 2)))


def print_banner(out: Console | None = None):
    out = out or console
    title = Text.assemble(("SecScan Agent", "bold"), (f"  v{VERSION}", "dim"))
    out.print(Panel(Text.assemble(title, "\n", ("Agente inteligente de revisión de seguridad", "grey70")),
                    box=box.ROUNDED, border_style="cyan", padding=(0, 2), expand=False))


def print_final(results: dict, insights: dict, out: Console | None = None):
    """Veredicto, hallazgos principales y ubicación del reporte."""
    out = out or console
    level_style = {"critical": "bold red", "serious": "bold dark_orange", "warning": "yellow", "good": "bold green"}
    level_text = {
        "critical": "No apto para producción",
        "serious": "Requiere correcciones antes de desplegar",
        "warning": "Aceptable con observaciones",
        "good": "Sin riesgos relevantes detectados",
    }
    style = level_style[insights["verdict"]]

    top = [e for e in insights["entries"] if not e["is_threat"]][:8]
    body = []
    head = Table.grid(padding=(0, 2))
    head.add_column(); head.add_column()
    head.add_row("[dim]Riesgo[/]", f"[{style}]{insights['risk_score']}/100[/]")
    head.add_row("[dim]Veredicto[/]", f"[{style}]{level_text[insights['verdict']]}[/]")
    head.add_row("[dim]Amenazas[/]", f"{insights['threat_events']} eventos de ataque en logs"
                 if insights["threat_events"] else "[dim]ninguna en logs[/]")
    body.append(head)

    if top:
        table = Table(box=box.SIMPLE_HEAD, show_edge=False, pad_edge=False, header_style="dim", title_justify="left")
        table.add_column("Sev.", no_wrap=True)
        table.add_column("Hallazgo", overflow="fold")
        table.add_column("Ubicación", style="cyan", overflow="fold")
        for e in top:
            loc = f"{e['path']}:{e['line']}" if e["line"] else e["path"]
            table.add_row(severity_text(e["severity"]), e["type"], loc)
        body.append(Text())
        body.append(table)

    from rich.console import Group
    report = results.get("report_path")
    if report:
        body.append(Text.assemble(("\nReporte  ", "dim"), (report, "bold underline")))
    out.print()
    out.print(Panel(Group(*body), title="[bold]Resultado[/]", title_align="left",
                    border_style=style.replace("bold ", ""), box=box.ROUNDED, padding=(1, 2)))
