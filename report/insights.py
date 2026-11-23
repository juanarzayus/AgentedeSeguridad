"""
Insights — Convierte los hallazgos crudos en información para tomar decisiones.

Separa dos conceptos que el reporte nunca debe mezclar:
- Exposición: vulnerabilidades del proyecto (código, dependencias, configuración).
  Es lo que determina el puntaje de riesgo y el veredicto.
- Amenazas: eventos de ataque en los logs. Indican que alguien está atacando,
  no que el código sea vulnerable; se informan en su propia sección.

Y agrupa los hallazgos por la acción que los corrige ("rotar credenciales"
resuelve muchos hallazgos de una vez), que es como un equipo planifica el trabajo.
"""

from __future__ import annotations

import math
import os
import re
from collections import Counter, defaultdict

from agent.findings import SEVERITY_ORDER
from tools.secret_scanner import redact_line

SEVERITIES = ["CRITICA", "ALTA", "MEDIA", "BAJA"]
SEVERITY_WEIGHT = {"CRITICA": 10, "ALTA": 5, "MEDIA": 2, "BAJA": 0.5}
CONFIDENCE_FACTOR = {"ALTA": 1.0, "MEDIA": 0.75, "BAJA": 0.4}
SCORE_SCALE = 60
THREAT_TOOLS = {"LogAnalyzer"}
SNIPPET_RADIUS = 3

# Acción correctiva → (CWEs que cubre, esfuerzo estimado)
ACTIONS = [
    ("rotate_credentials", {"CWE-798"}, "low"),
    ("parametrize_sql", {"CWE-89"}, "low"),
    ("update_dependencies", {"CWE-1395"}, "low"),
    ("output_encoding", {"CWE-79", "CWE-1336", "CWE-95"}, "medium"),
]


def _action_for(finding: dict) -> str:
    if finding.get("tool") in THREAT_TOOLS:
        return "contain_threats"
    cwe = finding.get("cwe", "")
    for key, cwes, _ in ACTIONS:
        if cwe in cwes:
            return key
    if finding.get("tool") == "ConfigAuditor":
        return "harden_config"
    return "other"


EFFORT = {key: effort for key, _, effort in ACTIONS}
EFFORT.update({"harden_config": "medium", "contain_threats": "medium", "other": "medium"})


def _rank(severity: str) -> int:
    return SEVERITY_ORDER.get(severity, 4)


def risk_score(findings: list[dict]) -> int:
    points = sum(SEVERITY_WEIGHT.get(f.get("severity"), 0) * CONFIDENCE_FACTOR.get(f.get("confidence"), 0.75)
                 for f in findings)
    return round(100 * (1 - math.exp(-points / SCORE_SCALE)))


def verdict(counts: Counter) -> tuple[str, int]:
    """Devuelve (nivel, n) donde nivel ∈ critical|serious|warning|good."""
    if counts.get("CRITICA"):
        return "critical", counts["CRITICA"]
    if counts.get("ALTA"):
        return "serious", counts["ALTA"]
    if counts.get("MEDIA") or counts.get("BAJA"):
        return "warning", counts.get("MEDIA", 0) + counts.get("BAJA", 0)
    return "good", 0


def relative_path(path: str, target: str) -> str:
    try:
        rel = os.path.relpath(path, target)
    except ValueError:
        return path
    return path if rel.startswith("..") else rel


class SnippetReader:
    """Lee fragmentos de código alrededor de una línea, con los secretos redactados."""

    def __init__(self):
        self._cache: dict[str, list[str]] = {}

    def _lines(self, path: str) -> list[str]:
        if path not in self._cache:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    self._cache[path] = f.read().splitlines()
            except OSError:
                self._cache[path] = []
        return self._cache[path]

    def get(self, path: str, line: int) -> list[dict]:
        if line <= 0 or not os.path.isfile(path):
            return []
        lines = self._lines(path)
        start, end = max(1, line - SNIPPET_RADIUS), min(len(lines), line + SNIPPET_RADIUS)
        return [{"number": n, "text": redact_line(lines[n - 1])[:200], "highlight": n == line}
                for n in range(start, end + 1)]


def _localized(finding: dict, field: str, lang: str) -> str:
    return finding.get(f"{field}_{lang}") or finding.get(field, "")


_IP_REGEX = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def build_insights(results: dict, lang: str = "es") -> dict:
    from report.i18n import Translator
    brute_force_label = Translator(lang)("brute_force")
    target = results.get("target", "")
    findings = results.get("findings", [])
    exposure = [f for f in findings if f.get("tool") not in THREAT_TOOLS]
    threats = [f for f in findings if f.get("tool") in THREAT_TOOLS]

    exposure_counts = Counter(f.get("severity") for f in exposure)
    level, level_n = verdict(exposure_counts)

    # ── Detalle de cada hallazgo, listo para la plantilla ──
    snippets = SnippetReader()
    items = []
    for i, f in enumerate(findings, 1):
        path = f.get("file", "")
        is_threat = f.get("tool") in THREAT_TOOLS
        items.append({
            "id": i,
            "severity": f.get("severity", "BAJA"),
            "confidence": f.get("confidence", "MEDIA"),
            "type": f.get("type", ""),
            "tool": f.get("tool", ""),
            "tools": [f.get("tool", "")] + list(f.get("also_detected_by", [])),
            "cwe": f.get("cwe", ""),
            "owasp": f.get("owasp", ""),
            "path": relative_path(path, target) if os.path.isabs(path) or os.path.exists(path) else path,
            "line": f.get("line", 0),
            "content": f.get("content", ""),
            "description": _localized(f, "description", lang),
            "recommendation": _localized(f, "recommendation", lang),
            "snippet": [] if is_threat else snippets.get(path, f.get("line", 0)),
            "is_threat": is_threat,
            "action": _action_for(f),
        })

    # ── Acciones prioritarias ──
    groups: dict[str, list[dict]] = defaultdict(list)
    for item in items:
        groups[item["action"]].append(item)
    actions = []
    for key, group in groups.items():
        actions.append({
            "key": key,
            "count": len(group),
            # Para amenazas "archivos" no aplica (son logs): la plantilla muestra un guion
            "files": None if key == "contain_threats" else len({g["path"] for g in group}),
            "max_severity": min((g["severity"] for g in group), key=_rank),
            "effort": EFFORT.get(key, "medium"),
            "severity_counts": Counter(g["severity"] for g in group),
        })
    actions.sort(key=lambda a: (_rank(a["max_severity"]), -a["count"]))

    # ── Categorías OWASP (solo exposición) ──
    owasp = Counter(f.get("owasp") for f in exposure if f.get("owasp"))
    owasp_rows = [{"label": k, "value": v} for k, v in owasp.most_common()]

    # ── Archivos más afectados, con desglose por severidad ──
    per_file: dict[str, Counter] = defaultdict(Counter)
    for item in items:
        if not item["is_threat"]:
            per_file[item["path"]][item["severity"]] += 1
    file_rows = sorted(
        ({"label": path, "segments": {s: c[s] for s in SEVERITIES if c[s]}, "value": sum(c.values())}
         for path, c in per_file.items()),
        key=lambda r: (-r["value"], r["label"]),
    )[:6]

    # ── Amenazas ──
    ip_events: dict[str, Counter] = defaultdict(Counter)
    active_ips = set()
    for f in threats:
        match = _IP_REGEX.search(f.get("matched_value", "") or f.get("content", ""))
        if not match:
            continue
        ip = match.group(1)
        if f.get("type") == "Atacante activo detectado":
            active_ips.add(ip)
        elif f.get("type") == "Fuerza bruta detectada":
            # Hallazgo agregado: "IP x: N intentos fallidos" → N eventos de fuerza bruta
            attempts = re.search(r"(\d+)\s+intentos", f.get("content", ""))
            ip_events[ip][brute_force_label] += int(attempts.group(1)) if attempts else 1
        elif f.get("line", 0) > 0:
            ip_events[ip][f.get("type", "")] += 1
    threat_rows = sorted(
        ({"ip": ip, "events": sum(c.values()), "types": [t for t, _ in c.most_common()],
          "active": ip in active_ips} for ip, c in ip_events.items()),
        key=lambda r: (-r["events"], r["ip"]),
    )

    return {
        "risk_score": risk_score(exposure),
        "verdict": level,
        "verdict_n": level_n,
        "exposure_total": len(exposure),
        "threat_total": len(threats),
        "severity_counts": {s: exposure_counts.get(s, 0) for s in SEVERITIES},
        "all_severity_counts": {s: sum(1 for f in findings if f.get("severity") == s) for s in SEVERITIES},
        "actions": actions,
        "owasp_rows": owasp_rows,
        "file_rows": file_rows,
        "threat_rows": threat_rows,
        "threat_events": sum(r["events"] for r in threat_rows),
        "active_attackers": len(active_ips),
        "entries": items,
        "tools": sorted({i["tool"] for i in items}),
    }
