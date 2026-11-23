"""
Gestor de análisis para la interfaz web.

Cada análisis corre en un hilo de fondo. El orquestador emite eventos a un
`WebReporter`, que los guarda en memoria; el navegador los consulta por
polling (`/api/scans/<id>?since=N`) y los anima.

Restricciones de seguridad:
- Un solo análisis a la vez (evita que la herramienta se use para agotar recursos).
- Los reportes se identifican por un UUID generado aquí; el cliente nunca
  envía rutas de archivo para descargar, así que no hay path traversal posible.
"""

from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field

from agent.ui import NullReporter
from report.generator import PdfUnavailableError, ReportGenerator
from report.insights import build_insights
from skills.security_review import SecurityReviewSkill

log = logging.getLogger("secscan.web")

MAX_HISTORY = 20
DOWNLOAD_FORMATS = ("html", "pdf", "json")


class WebReporter(NullReporter):
    """Convierte los eventos del orquestador en datos JSON serializables."""

    def __init__(self, scan: "Scan"):
        self.scan = scan

    def _emit(self, kind: str, **data):
        self.scan.add_event(kind, data)

    def phase(self, number, key):
        self._emit("phase", number=number, key=key)

    def context(self, ctx):
        self._emit("context", total_files=ctx.total_files, python=ctx.has_python_files,
                   js=ctx.has_js_files, html=ctx.has_html_files, dependencies=ctx.has_requirements,
                   config=ctx.has_config_files or ctx.has_env_files, logs=ctx.has_log_files,
                   ignored=ctx.ignored_files)

    def plan(self, plan, available_tools):
        self._emit("plan", available=available_tools, skipped=list(plan.skipped),
                   steps=[{"order": s["order"], "tool": s["tool"], "reason": s["reason"]} for s in plan.steps])

    @contextmanager
    def step_start(self, index, total, tool):
        self._emit("step_start", index=index, total=total, tool=tool)
        yield

    def step_end(self, index, total, entry):
        self._emit("step_end", index=index, total=total, tool=entry["tool"], status=entry["status"],
                   findings=entry.get("findings_count", 0), seconds=entry.get("time_seconds", 0),
                   error="La herramienta falló" if entry["status"] == "error" else None)


@dataclass
class Scan:
    id: str
    target: str
    logs: str | None
    skill: str
    lang: str
    output_dir: str
    status: str = "queued"  # queued | running | done | error
    created_at: float = field(default_factory=time.time)
    events: list[dict] = field(default_factory=list)
    error: str | None = None
    results: dict | None = None
    summary: dict | None = None
    files: dict[str, str] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add_event(self, kind: str, data: dict):
        with self._lock:
            self.events.append({"seq": len(self.events), "type": kind, **data})

    def snapshot(self, since: int = 0) -> dict:
        with self._lock:
            events = self.events[since:]
        return {
            "id": self.id,
            "status": self.status,
            "target": self.target,
            "skill": self.skill,
            "lang": self.lang,
            "created_at": self.created_at,
            "events": events,
            "next": since + len(events),
            "error": self.error,
            "summary": self.summary if self.status == "done" else None,
        }

    def brief(self) -> dict:
        s = self.summary or {}
        return {"id": self.id, "status": self.status, "target": self.target, "skill": self.skill,
                "created_at": self.created_at, "risk_score": s.get("risk_score"),
                "verdict": s.get("verdict"), "total": s.get("total")}


def _summarize(results: dict, lang: str) -> dict:
    ins = build_insights(results, lang)
    top = [
        {"severity": e["severity"], "type": e["type"],
         "location": f"{e['path']}:{e['line']}" if e["line"] else e["path"], "cwe": e["cwe"]}
        for e in ins["entries"] if not e["is_threat"]
    ][:6]
    return {
        "risk_score": ins["risk_score"],
        "verdict": ins["verdict"],
        "verdict_n": ins["verdict_n"],
        "total": results.get("total_findings", 0),
        "exposure_total": ins["exposure_total"],
        "threat_events": ins["threat_events"],
        "active_attackers": ins["active_attackers"],
        "severity_counts": ins["severity_counts"],
        "actions": [{"key": a["key"], "count": a["count"], "max_severity": a["max_severity"],
                     "effort": a["effort"]} for a in ins["actions"]],
        "top": top,
        "tool_errors": results.get("tool_errors", 0),
        "seconds": results.get("total_time_seconds", 0),
    }


class ScanManager:
    def __init__(self, base_output_dir: str):
        self.base_output_dir = base_output_dir
        self._scans: dict[str, Scan] = {}
        self._order: list[str] = []
        self._lock = threading.Lock()
        self._busy = threading.Lock()  # un análisis a la vez
        self._generator = ReportGenerator()

    # ── Consulta ──
    def get(self, scan_id: str) -> Scan | None:
        return self._scans.get(scan_id)

    def history(self) -> list[dict]:
        with self._lock:
            return [self._scans[i].brief() for i in reversed(self._order)]

    @property
    def busy(self) -> bool:
        return self._busy.locked()

    # ── Ejecución ──
    def start(self, target: str, logs: str | None, skill: str, lang: str) -> Scan:
        if not self._busy.acquire(blocking=False):
            raise RuntimeError("busy")
        scan_id = uuid.uuid4().hex
        scan = Scan(id=scan_id, target=target, logs=logs, skill=skill, lang=lang,
                    output_dir=os.path.join(self.base_output_dir, scan_id))
        with self._lock:
            self._scans[scan_id] = scan
            self._order.append(scan_id)
            while len(self._order) > MAX_HISTORY:
                self._scans.pop(self._order.pop(0), None)
        threading.Thread(target=self._run, args=(scan,), daemon=True, name=f"scan-{scan_id[:8]}").start()
        return scan

    def _run(self, scan: Scan):
        try:
            scan.status = "running"
            skill = SecurityReviewSkill(verbose=False, reporter=WebReporter(scan))
            results = skill.execute(scan.skill, scan.target, scan.logs, output_format="html",
                                    output_dir=scan.output_dir, lang=scan.lang)
            if "error" in results:
                scan.error = "No se pudo analizar el directorio."
                scan.status = "error"
                return
            scan.results = results
            scan.files["html"] = results["report_path"]
            scan.summary = _summarize(results, scan.lang)
            scan.status = "done"
            scan.add_event("done", {"summary": scan.summary})
        except Exception:  # nunca exponer trazas al navegador; sí registrarlas en la terminal
            log.exception("Fallo el análisis %s", scan.id)
            scan.error = "Error inesperado durante el análisis."
            scan.status = "error"
        finally:
            if scan.status == "error":
                scan.add_event("error", {"message": scan.error})
            self._busy.release()

    def report_file(self, scan: Scan, fmt: str) -> str:
        """Devuelve la ruta del reporte en `fmt`, generándolo bajo demanda."""
        if fmt not in DOWNLOAD_FORMATS or scan.status != "done":
            raise ValueError(fmt)
        if fmt not in scan.files:
            scan.files[fmt] = self._generator.generate(scan.results, format=fmt,
                                                       output_dir=scan.output_dir, lang=scan.lang)
        return scan.files[fmt]


__all__ = ["ScanManager", "Scan", "PdfUnavailableError", "DOWNLOAD_FORMATS"]
