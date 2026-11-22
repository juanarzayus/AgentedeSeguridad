"""
Findings — Modelo de datos común para los hallazgos de todas las herramientas.

Todas las tools construyen un `Finding` y lo serializan con `to_dict()`, de modo
que el orquestador y el generador de reportes trabajan siempre con la misma
estructura. Este módulo también contiene utilidades compartidas:

- `mask_secret` / `mask_in_line`: enmascarar secretos antes de que lleguen al reporte.
- `deduplicate`: fusionar hallazgos repetidos (mismo archivo, línea y CWE),
  aunque provengan de herramientas distintas.
- `is_suppressed`: soporte para comentarios `# secscan: ignore` / `# nosec`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict

SEVERITY_ORDER = {"CRITICA": 0, "ALTA": 1, "MEDIA": 2, "BAJA": 3}

# Comentarios en línea que suprimen un hallazgo en esa línea
SUPPRESSION_REGEX = re.compile(r"(?:secscan:\s*ignore|\bnosec\b)", re.IGNORECASE)


@dataclass
class Finding:
    """Un hallazgo de seguridad reportado por una herramienta."""
    tool: str
    file: str
    line: int
    content: str
    type: str
    severity: str  # CRITICA, ALTA, MEDIA, BAJA
    description: str
    recommendation: str
    matched_value: str = ""
    cwe: str = ""            # Ej: "CWE-89"
    owasp: str = ""          # Ej: "A03:2021 Injection"
    confidence: str = "MEDIA"  # ALTA, MEDIA, BAJA
    also_detected_by: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def mask_secret(value: str) -> str:
    """
    Enmascara un secreto dejando visible solo un prefijo mínimo para identificarlo.

    Los valores cortos se ocultan por completo: revelar 8+4 caracteres de una
    contraseña de 13 equivale a publicarla.
    """
    if len(value) >= 20:
        return value[:4] + "****" + value[-2:]
    if len(value) >= 10:
        return value[:2] + "****"
    return "****"


def mask_in_line(line: str, secrets: list[str]) -> str:
    """Reemplaza cada secreto dentro de la línea por su versión enmascarada."""
    # Los más largos primero, para que un secreto contenido en otro no deje restos
    for secret in sorted(set(secrets), key=len, reverse=True):
        if secret:
            line = line.replace(secret, mask_secret(secret))
    return line


def is_suppressed(line_text: str) -> bool:
    """True si la línea contiene un comentario de supresión."""
    return bool(SUPPRESSION_REGEX.search(line_text))


def deduplicate(findings: list[dict]) -> list[dict]:
    """
    Fusiona hallazgos que describen el mismo problema.

    Clave: (archivo, línea, CWE). Si no hay CWE se usa el tipo. Se conserva el
    hallazgo de mayor severidad y se anotan las demás herramientas en
    `also_detected_by`. Los hallazgos agregados (line == 0) se agrupan por
    contenido para no fusionar, por ejemplo, dos CVE distintos.
    """
    merged: dict[tuple, dict] = {}
    for f in findings:
        if f.get("line", 0) == 0:
            key = (f.get("file"), 0, f.get("type"), f.get("content"))
        else:
            key = (f.get("file"), f.get("line"), f.get("cwe") or f.get("type"))

        existing = merged.get(key)
        if existing is None:
            merged[key] = {**f, "also_detected_by": list(f.get("also_detected_by", []))}
            continue

        new_rank = SEVERITY_ORDER.get(f.get("severity"), 4)
        old_rank = SEVERITY_ORDER.get(existing.get("severity"), 4)
        if new_rank < old_rank:
            winner, loser = {**f, "also_detected_by": list(f.get("also_detected_by", []))}, existing
            merged[key] = winner
        else:
            winner, loser = existing, f

        others = [loser.get("tool")] + loser.get("also_detected_by", [])
        for tool in others:
            if tool and tool != winner.get("tool") and tool not in winner["also_detected_by"]:
                winner["also_detected_by"].append(tool)

    return list(merged.values())
