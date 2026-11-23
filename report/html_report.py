"""
HTML/PDF report — Renderiza el reporte visual con Jinja2 y, opcionalmente, a PDF con WeasyPrint.

Diseño:
- Una sola plantilla (`templates/report.html.j2`) con dos modos:
  * screen: interactivo (filtros, búsqueda, tema claro/oscuro), para el navegador.
  * print:  maquetado A4 con encabezado/pie y numeración, para el PDF.
- Todo es autocontenido: fuentes (Inter, JetBrains Mono; licencia OFL) e íconos
  (Lucide; licencia ISC) se incrustan, y los gráficos son HTML/CSS + SVG
  vectoriales. El reporte funciona sin internet y el PDF se ve nítido a cualquier zoom.
- Autoescape activado: todo lo que proviene del proyecto analizado se escapa.
"""

from __future__ import annotations

import base64
import math
import os
import re
from datetime import datetime
from functools import lru_cache

from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup

from report.i18n import Translator
from report.insights import SEVERITIES, build_insights

HERE = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(HERE, "assets")
VERSION = "1.1.0"

STATUS_COLOR = {
    "critical": "#d03b3b",
    "serious": "#ec835a",
    "warning": "#fab219",
    "good": "#0ca30c",
}
SEVERITY_STATUS = {"CRITICA": "critical", "ALTA": "serious", "MEDIA": "warning", "BAJA": "low"}
SEVERITY_ICON = {"CRITICA": "octagon-alert", "ALTA": "triangle-alert", "MEDIA": "circle-alert", "BAJA": "info"}

FONTS = [
    ("Inter", 400, "inter-400.woff2"),
    ("Inter", 500, "inter-500.woff2"),
    ("Inter", 600, "inter-600.woff2"),
    ("Inter", 700, "inter-700.woff2"),
    ("JetBrains Mono", 400, "jbm-400.woff2"),
    ("JetBrains Mono", 600, "jbm-600.woff2"),
]


@lru_cache(maxsize=None)
def font_faces_css() -> str:
    rules = []
    for family, weight, filename in FONTS:
        path = os.path.join(ASSETS, "fonts", filename)
        if not os.path.isfile(path):
            continue
        with open(path, "rb") as f:
            data = base64.b64encode(f.read()).decode("ascii")
        rules.append(
            f"@font-face{{font-family:'{family}';font-style:normal;font-weight:{weight};"
            f"font-display:swap;src:url(data:font/woff2;base64,{data}) format('woff2');}}"
        )
    return "\n".join(rules)


@lru_cache(maxsize=None)
def _icon_source(name: str) -> str:
    path = os.path.join(ASSETS, "icons", f"{name}.svg")
    with open(path, "r", encoding="utf-8") as f:
        svg = f.read()
    svg = re.sub(r"<!--.*?-->", "", svg, flags=re.S).strip()
    # Quitar width/height/class originales: el tamaño lo define el CSS
    svg = re.sub(r'\s(width|height|class)="[^"]*"', "", svg)
    return re.sub(r"\s+", " ", svg)


def icon(name: str, cls: str = "") -> Markup:
    """Ícono Lucide en línea. `name` viene de la plantilla, nunca del proyecto analizado."""
    svg = _icon_source(name)
    return Markup(svg.replace("<svg", f'<svg class="icon {cls}" aria-hidden="true" width="16" height="16"', 1))


def gauge(score: int, level: str) -> Markup:
    """Medidor semicircular 0–100 (SVG vectorial)."""
    cx, cy, r, stroke = 100, 100, 80, 14
    track = f"M {cx - r} {cy} A {r} {r} 0 0 1 {cx + r} {cy}"
    parts = [f'<path d="{track}" class="gauge-track" fill="none" stroke-width="{stroke}" stroke-linecap="round"/>']
    if score > 0:
        angle = math.pi * (1 - min(score, 100) / 100)
        x, y = cx + r * math.cos(angle), cy - r * math.sin(angle)
        value = f"M {cx - r} {cy} A {r} {r} 0 0 1 {x:.2f} {y:.2f}"
        parts.append(f'<path d="{value}" fill="none" stroke="{STATUS_COLOR[level]}" '
                     f'stroke-width="{stroke}" stroke-linecap="round"/>')
    svg = (f'<svg class="gauge" viewBox="0 0 200 112" role="img" aria-label="{int(score)}/100">'
           f'<title>{int(score)}/100</title>{"".join(parts)}</svg>')
    return Markup(svg)


def css_string(value: str) -> Markup:
    """
    Valor seguro para un string CSS dentro de <style>.

    En <style> el escapado HTML no aplica (es texto crudo), así que se descarta
    todo carácter que pueda cerrar el string o la etiqueta.
    """
    return Markup(re.sub(r"[^\w\s.\-·:/()]", "", str(value))[:80])


def _environment() -> Environment:
    env = Environment(
        loader=FileSystemLoader(os.path.join(HERE, "templates")),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.globals.update(icon=icon, gauge=gauge, SEVERITIES=SEVERITIES,
                       SEVERITY_STATUS=SEVERITY_STATUS, SEVERITY_ICON=SEVERITY_ICON)
    env.filters["pct"] = lambda part, total: 0 if not total else round(100 * part / total, 2)
    env.filters["css_string"] = css_string
    return env


def render_html(results: dict, lang: str = "es", mode: str = "screen") -> str:
    t = Translator(lang)
    insights = build_insights(results, t.lang)
    now = datetime.now()
    context = {
        "t": t,
        "lang": t.lang,
        "mode": mode,
        "version": VERSION,
        "results": results,
        "ins": insights,
        "generated_at": now.strftime("%Y-%m-%d %H:%M"),
        "project_name": os.path.basename(os.path.abspath(results.get("target", ""))) or results.get("target", ""),
        "font_faces": Markup(font_faces_css()),
        "plan": results.get("plan", {}),
        "execution_log": results.get("execution_log", []),
        "context": results.get("context", {}),
    }
    return _environment().get_template("report.html.j2").render(**context)


class PdfUnavailableError(RuntimeError):
    pass


def render_pdf(results: dict, output_path: str, lang: str = "es") -> str:
    try:
        from weasyprint import HTML
    except (ImportError, OSError) as e:  # OSError: faltan librerías del sistema (Pango/GTK)
        raise PdfUnavailableError(
            "WeasyPrint no está disponible. Instalar con: pip install -r requirements-pdf.txt "
            "(en Windows requiere además GTK3: https://doc.courtbouillon.org/weasyprint/stable/first_steps.html). "
            f"Detalle: {e}"
        ) from e
    import logging
    import warnings
    # Avisos internos de WeasyPrint (p. ej. HarfBuzz-Subset ausente) no aportan al usuario
    logging.getLogger("weasyprint").setLevel(logging.ERROR)
    logging.getLogger("fontTools").setLevel(logging.ERROR)
    html = render_html(results, lang=lang, mode="print")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        HTML(string=html, base_url=HERE).write_pdf(output_path)
    return output_path
