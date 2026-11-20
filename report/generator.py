"""
ReportGenerator — Generador de reportes de seguridad.

Genera reportes en tres formatos:
- Texto plano (terminal con colores)
- HTML (reporte visual interactivo)
- JSON (para integración con otras herramientas)
"""

import json
import os
from datetime import datetime


class ReportGenerator:
    """Genera reportes de seguridad en múltiples formatos."""

    def generate(self, results: dict, format: str = "text", output_dir: str = "reports") -> str:
        """
        Genera un reporte de seguridad.

        Args:
            results: Resultados del análisis del orquestador.
            format: Formato de salida (text, html, json).
            output_dir: Directorio donde guardar el reporte.

        Returns:
            Ruta al archivo de reporte generado.
        """
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if format == "html":
            return self._generate_html(results, output_dir, timestamp)
        elif format == "json":
            return self._generate_json(results, output_dir, timestamp)
        else:
            return self._generate_text(results, output_dir, timestamp)

    def _generate_text(self, results: dict, output_dir: str, timestamp: str) -> str:
        """Genera reporte en texto plano."""
        filepath = os.path.join(output_dir, f"security_report_{timestamp}.txt")

        lines = [
            "=" * 70,
            "  REPORTE DE SEGURIDAD — SecScan Agent",
            "=" * 70,
            "",
            f"  Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"  Proyecto: {results.get('target', 'N/A')}",
            f"  Total hallazgos: {results.get('total_findings', 0)}",
            f"  Tiempo de análisis: {results.get('total_time_seconds', 0)}s",
            "",
            "-" * 70,
            "  RESUMEN POR SEVERIDAD",
            "-" * 70,
        ]

        severity_counts = results.get("severity_counts", {})
        for sev in ["CRITICA", "ALTA", "MEDIA", "BAJA"]:
            count = severity_counts.get(sev, 0)
            icon = {"CRITICA": "[!!!]", "ALTA": "[!!]", "MEDIA": "[!]", "BAJA": "[i]"}.get(sev, "")
            lines.append(f"  {icon} {sev}: {count}")

        lines.extend(["", "-" * 70, "  HALLAZGOS DETALLADOS", "-" * 70, ""])

        for i, finding in enumerate(results.get("findings", []), 1):
            sev = finding.get("severity", "?")
            lines.extend([
                f"  [{i}] {sev} — {finding.get('type', 'N/A')}",
                f"      Herramienta: {finding.get('tool', 'N/A')}",
                f"      Archivo: {finding.get('file', 'N/A')}:{finding.get('line', 0)}",
                f"      Código: {finding.get('content', 'N/A')[:100]}",
                f"      Descripción: {finding.get('description', 'N/A')}",
                f"      Recomendación: {finding.get('recommendation', 'N/A')}",
                "",
            ])

        lines.extend(["", "-" * 70, "  PLAN DE EJECUCIÓN DEL AGENTE", "-" * 70, ""])

        plan = results.get("plan", {})
        for step in plan.get("steps", []):
            lines.append(f"  Paso {step.get('order', '?')}: [{step.get('tool', '?')}]")
            lines.append(f"    Razonamiento: {step.get('reason', 'N/A')[:120]}")
            lines.append("")

        lines.extend(["", "=" * 70, "  Generado por SecScan Agent", "=" * 70])

        report_text = "\n".join(lines)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(report_text)

        # También imprimir en consola
        print(report_text)

        return filepath

    def _generate_json(self, results: dict, output_dir: str, timestamp: str) -> str:
        """Genera reporte en formato JSON."""
        filepath = os.path.join(output_dir, f"security_report_{timestamp}.json")

        report = {
            "metadata": {
                "agent": "SecScan Agent",
                "version": "1.0.0",
                "generated_at": datetime.now().isoformat(),
                "target": results.get("target"),
                "total_time_seconds": results.get("total_time_seconds"),
            },
            "summary": {
                "total_findings": results.get("total_findings", 0),
                "severity_counts": results.get("severity_counts", {}),
                "tool_counts": results.get("tool_counts", {}),
                "risk_level": self._calculate_risk_level(results),
            },
            "findings": results.get("findings", []),
            "execution": {
                "plan": results.get("plan", {}),
                "log": results.get("execution_log", []),
            },
            "context": results.get("context", {}),
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        return filepath

    def _generate_html(self, results: dict, output_dir: str, timestamp: str) -> str:
        """Genera reporte en HTML con diseño visual."""
        filepath = os.path.join(output_dir, f"security_report_{timestamp}.html")

        findings = results.get("findings", [])
        severity_counts = results.get("severity_counts", {})
        total = results.get("total_findings", 0)
        risk_level = self._calculate_risk_level(results)

        # Generar filas de la tabla de hallazgos
        findings_rows = ""
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "BAJA")
            sev_class = {
                "CRITICA": "severity-critical",
                "ALTA": "severity-high",
                "MEDIA": "severity-medium",
                "BAJA": "severity-low",
            }.get(sev, "severity-low")
            sev_icon = {
                "CRITICA": "🔴",
                "ALTA": "🟠",
                "MEDIA": "🟡",
                "BAJA": "🔵",
            }.get(sev, "⚪")

            # Escapar HTML
            content = (f.get("content", "")[:100]
                       .replace("&", "&amp;")
                       .replace("<", "&lt;")
                       .replace(">", "&gt;"))

            findings_rows += f"""
            <tr>
                <td>{i}</td>
                <td><span class="{sev_class}">{sev_icon} {sev}</span></td>
                <td>{f.get('tool', 'N/A')}</td>
                <td>{f.get('type', 'N/A')}</td>
                <td><code>{os.path.basename(f.get('file', ''))}</code>:{f.get('line', 0)}</td>
                <td><code>{content}</code></td>
                <td>{f.get('description', '')[:120]}</td>
                <td>{f.get('recommendation', '')[:120]}</td>
            </tr>"""

        # Generar pasos del plan
        plan_steps = ""
        for step in results.get("plan", {}).get("steps", []):
            plan_steps += f"""
            <div class="plan-step">
                <strong>Paso {step.get('order', '?')}:</strong> [{step.get('tool', '?')}]<br>
                <em>{step.get('reason', 'N/A')[:200]}</em>
            </div>"""

        # Generar log de ejecución
        exec_log = ""
        for entry in results.get("execution_log", []):
            status_icon = "✅" if entry.get("status") == "success" else "❌"
            exec_log += f"""
            <tr>
                <td>{entry.get('step', '?')}</td>
                <td>{entry.get('tool', '?')}</td>
                <td>{status_icon} {entry.get('status', '?')}</td>
                <td>{entry.get('findings_count', 0)}</td>
                <td>{entry.get('time_seconds', 0)}s</td>
            </tr>"""

        risk_color = {
            "CRÍTICO": "#dc3545",
            "ALTO": "#fd7e14",
            "MEDIO": "#ffc107",
            "BAJO": "#28a745",
        }.get(risk_level, "#6c757d")

        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ SecScan Agent — Reporte de Seguridad</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            line-height: 1.6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        
        header {{
            background: linear-gradient(135deg, #161b22 0%, #1a2332 100%);
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 24px;
            text-align: center;
        }}
        header h1 {{
            color: #58a6ff;
            font-size: 2em;
            margin-bottom: 8px;
        }}
        header p {{ color: #8b949e; }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .summary-card {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        .summary-card .number {{
            font-size: 2.5em;
            font-weight: bold;
        }}
        .summary-card .label {{
            color: #8b949e;
            font-size: 0.9em;
            margin-top: 4px;
        }}

        .risk-badge {{
            display: inline-block;
            padding: 8px 24px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 1.1em;
            color: white;
            background: {risk_color};
        }}

        section {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 24px;
        }}
        section h2 {{
            color: #58a6ff;
            margin-bottom: 16px;
            padding-bottom: 8px;
            border-bottom: 1px solid #30363d;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85em;
        }}
        th {{
            background: #21262d;
            color: #58a6ff;
            padding: 10px 12px;
            text-align: left;
            position: sticky;
            top: 0;
        }}
        td {{
            padding: 8px 12px;
            border-bottom: 1px solid #21262d;
            vertical-align: top;
        }}
        tr:hover {{ background: #1c2128; }}

        .severity-critical {{ 
            color: #f85149; 
            font-weight: bold; 
        }}
        .severity-high {{ 
            color: #d29922;
            font-weight: bold;
        }}
        .severity-medium {{ 
            color: #58a6ff; 
        }}
        .severity-low {{ 
            color: #8b949e; 
        }}

        code {{
            background: #21262d;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.85em;
            word-break: break-all;
        }}

        .plan-step {{
            background: #21262d;
            border-left: 3px solid #58a6ff;
            padding: 12px 16px;
            margin-bottom: 12px;
            border-radius: 0 4px 4px 0;
        }}

        .color-critical {{ color: #f85149; }}
        .color-high {{ color: #d29922; }}
        .color-medium {{ color: #58a6ff; }}
        .color-low {{ color: #8b949e; }}

        footer {{
            text-align: center;
            padding: 20px;
            color: #484f58;
            font-size: 0.85em;
        }}

        .agent-flow {{
            display: flex;
            justify-content: center;
            gap: 8px;
            margin: 16px 0;
            flex-wrap: wrap;
        }}
        .flow-step {{
            background: #21262d;
            border: 1px solid #30363d;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.85em;
        }}
        .flow-arrow {{ color: #58a6ff; font-size: 1.2em; align-self: center; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ SecScan Agent</h1>
            <p>Reporte de Revisión de Seguridad</p>
            <br>
            <div class="agent-flow">
                <span class="flow-step">🔍 Observar</span>
                <span class="flow-arrow">→</span>
                <span class="flow-step">🧠 Razonar</span>
                <span class="flow-arrow">→</span>
                <span class="flow-step">⚡ Actuar</span>
                <span class="flow-arrow">→</span>
                <span class="flow-step">📊 Reportar</span>
            </div>
        </header>

        <!-- Resumen -->
        <div class="summary-grid">
            <div class="summary-card">
                <div class="number" style="color: #58a6ff;">{total}</div>
                <div class="label">Total Hallazgos</div>
            </div>
            <div class="summary-card">
                <div class="number color-critical">{severity_counts.get('CRITICA', 0)}</div>
                <div class="label">🔴 Críticos</div>
            </div>
            <div class="summary-card">
                <div class="number color-high">{severity_counts.get('ALTA', 0)}</div>
                <div class="label">🟠 Altos</div>
            </div>
            <div class="summary-card">
                <div class="number color-medium">{severity_counts.get('MEDIA', 0)}</div>
                <div class="label">🟡 Medios</div>
            </div>
            <div class="summary-card">
                <div class="number color-low">{severity_counts.get('BAJA', 0)}</div>
                <div class="label">🔵 Bajos</div>
            </div>
            <div class="summary-card">
                <div class="risk-badge">{risk_level}</div>
                <div class="label" style="margin-top: 8px;">Nivel de Riesgo</div>
            </div>
        </div>

        <!-- Hallazgos -->
        <section>
            <h2>🔍 Hallazgos Detallados</h2>
            <div style="overflow-x: auto;">
                <table>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Severidad</th>
                            <th>Herramienta</th>
                            <th>Tipo</th>
                            <th>Archivo</th>
                            <th>Código</th>
                            <th>Descripción</th>
                            <th>Recomendación</th>
                        </tr>
                    </thead>
                    <tbody>
                        {findings_rows}
                    </tbody>
                </table>
            </div>
        </section>

        <!-- Plan del Agente -->
        <section>
            <h2>🧠 Razonamiento del Agente — Plan de Ejecución</h2>
            <p style="color: #8b949e; margin-bottom: 16px;">
                El agente analizó el proyecto y decidió ejecutar las siguientes herramientas,
                en este orden, basándose en el tipo de archivos encontrados:
            </p>
            {plan_steps}
        </section>

        <!-- Log de Ejecución -->
        <section>
            <h2>⚡ Log de Ejecución</h2>
            <table>
                <thead>
                    <tr>
                        <th>Paso</th>
                        <th>Herramienta</th>
                        <th>Estado</th>
                        <th>Hallazgos</th>
                        <th>Tiempo</th>
                    </tr>
                </thead>
                <tbody>
                    {exec_log}
                </tbody>
            </table>
        </section>

        <!-- Metadata -->
        <section>
            <h2>📋 Información del Análisis</h2>
            <table>
                <tr><td><strong>Proyecto analizado</strong></td><td>{results.get('target', 'N/A')}</td></tr>
                <tr><td><strong>Fecha</strong></td><td>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
                <tr><td><strong>Tiempo total</strong></td><td>{results.get('total_time_seconds', 0)} segundos</td></tr>
                <tr><td><strong>Archivos analizados</strong></td><td>{results.get('context', {}).get('total_files', 0)}</td></tr>
                <tr><td><strong>Herramientas ejecutadas</strong></td><td>{len(results.get('execution_log', []))}</td></tr>
            </table>
        </section>

        <footer>
            Generado por SecScan Agent v1.0 — Agente Inteligente de Revisión de Seguridad<br>
            Proyecto Final — Inteligencia Artificial
        </footer>
    </div>
</body>
</html>"""

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        return filepath

    def _calculate_risk_level(self, results: dict) -> str:
        """Calcula el nivel de riesgo general del proyecto."""
        counts = results.get("severity_counts", {})
        if counts.get("CRITICA", 0) > 0:
            return "CRÍTICO"
        elif counts.get("ALTA", 0) >= 3:
            return "ALTO"
        elif counts.get("ALTA", 0) > 0 or counts.get("MEDIA", 0) >= 5:
            return "MEDIO"
        else:
            return "BAJO"
