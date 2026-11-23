"""
ReportGenerator — Generador de reportes de seguridad.

Formatos:
- text: texto plano (para archivar o adjuntar en un ticket)
- json: datos estructurados para integrar con otras herramientas
- html: reporte visual interactivo, autocontenido (ver report/html_report.py)
- pdf:  el mismo reporte maquetado en A4 con WeasyPrint
"""

import json
import os
from datetime import datetime

from report.html_report import VERSION, PdfUnavailableError, render_html, render_pdf
from report.i18n import DEFAULT_LANG, Translator
from report.insights import SEVERITIES, build_insights

FORMATS = ("text", "html", "json", "pdf")

__all__ = ["ReportGenerator", "FORMATS", "PdfUnavailableError"]


class ReportGenerator:
    """Genera reportes de seguridad en múltiples formatos."""

    def generate(self, results: dict, format: str = "text", output_dir: str = "reports",
                 lang: str = DEFAULT_LANG) -> str:
        """
        Genera un reporte de seguridad.

        Args:
            results: Resultados del análisis del orquestador.
            format: Formato de salida (text, html, json, pdf).
            output_dir: Directorio donde guardar el reporte.
            lang: Idioma del reporte (es, en).

        Returns:
            Ruta al archivo de reporte generado.

        Raises:
            PdfUnavailableError: si se pide PDF y WeasyPrint no está instalado.
        """
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.path.join(output_dir, f"security_report_{timestamp}")

        if format == "html":
            html = render_html(results, lang=lang, mode="screen")  # renderizar antes de abrir el archivo
            path = f"{base}.html"
            with open(path, "w", encoding="utf-8") as f:
                f.write(html)
            return path
        if format == "pdf":
            return render_pdf(results, f"{base}.pdf", lang=lang)
        if format == "json":
            return self._generate_json(results, f"{base}.json", lang)
        return self._generate_text(results, f"{base}.txt", lang)

    # ─────────────────────────────────────────────────────────

    def _generate_text(self, results: dict, filepath: str, lang: str) -> str:
        t = Translator(lang)
        ins = build_insights(results, t.lang)
        rule, thin = "=" * 72, "-" * 72

        lines = [
            rule,
            f"  SecScan Agent — {t('report_title')}",
            rule,
            f"  {t('date')}: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"  {t('project')}: {results.get('target', 'N/A')}",
            f"  {t('duration')}: {results.get('total_time_seconds', 0)} {t('seconds')}",
            "",
            f"  {t('risk_score')}: {ins['risk_score']}/100",
            f"  {t('verdict')}: {t('verdict_' + ins['verdict'])}",
            f"  {t('verdict_detail_' + ins['verdict'], n=ins['verdict_n'])}",
            "",
            thin,
            f"  {t('severity_distribution').upper()} ({t('exposure_note')})",
            thin,
        ]
        for sev in SEVERITIES:
            lines.append(f"  {t('sev_' + sev):<10} {ins['severity_counts'][sev]:>4}")
        lines.append(f"  {t('threats_note')}: {ins['threat_total']}")

        lines += ["", thin, f"  {t('priority_actions').upper()}", thin]
        for i, a in enumerate(ins["actions"], 1):
            lines.append(f"  {i}. {t('action_' + a['key'])}  "
                         f"[{t('sev_' + a['max_severity'])}, {a['count']} {t('col_findings').lower()}, "
                         f"{t('col_effort').lower()}: {t('effort_' + a['effort']).lower()}]")

        lines += ["", thin, f"  {t('detailed_findings').upper()}", thin, ""]
        for item in ins["entries"]:
            location = f"{item['path']}:{item['line']}" if item["line"] else item["path"]
            tools = ", ".join(item["tools"])
            lines += [
                f"  [{item['id']}] {t('sev_' + item['severity']).upper()} — {item['type']}",
                f"      {t('location')}: {location}",
                f"      CWE: {item['cwe'] or 'N/A'} | {t('conf_' + item['confidence'])} | {t('detected_by')}: {tools}",
                f"      {t('evidence')}: {item['content'][:100]}",
                f"      {t('risk')}: {item['description']}",
                f"      {t('fix')}: {item['recommendation']}",
                "",
            ]

        lines += ["", thin, f"  {t('agent_reasoning').upper()}", thin, ""]
        for step in results.get("plan", {}).get("steps", []):
            lines.append(f"  {step.get('order', '?')}. [{step.get('tool', '?')}] {step.get('reason', '')[:120]}")
        skipped = results.get("plan", {}).get("skipped_tools", [])
        if skipped:
            lines.append(f"  {t('skipped_tools')}: {', '.join(skipped)}")

        lines += ["", rule, f"  {t('generated_by')} v{VERSION}", rule]

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        return filepath

    def _generate_json(self, results: dict, filepath: str, lang: str) -> str:
        ins = build_insights(results, lang)
        report = {
            "metadata": {
                "agent": "SecScan Agent",
                "version": VERSION,
                "generated_at": datetime.now().isoformat(),
                "target": results.get("target"),
                "skill": results.get("skill_used"),
                "total_time_seconds": results.get("total_time_seconds"),
            },
            "summary": {
                "total_findings": results.get("total_findings", 0),
                "severity_counts": results.get("severity_counts", {}),
                "tool_counts": results.get("tool_counts", {}),
                "risk_score": ins["risk_score"],
                "verdict": ins["verdict"],
                "exposure_findings": ins["exposure_total"],
                "threat_events": ins["threat_total"],
                "priority_actions": [
                    {"action": a["key"], "max_severity": a["max_severity"], "findings": a["count"],
                     "files": a["files"], "effort": a["effort"]}
                    for a in ins["actions"]
                ],
                "suppressed": results.get("suppressed_count", 0),
                "merged_duplicates": results.get("merged_duplicates", 0),
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
