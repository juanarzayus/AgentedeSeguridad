"""
i18n — Textos del reporte en varios idiomas.

Para agregar un idioma: copiar el bloque "es", traducir los valores y
registrarlo en STRINGS. Las claves faltantes caen al español.

Nota: los textos de cada hallazgo (descripción y recomendación) los genera
cada herramienta y hoy están en español. Si una herramienta incluye
`description_<lang>` / `recommendation_<lang>` en el hallazgo, el reporte
los usa automáticamente.
"""

DEFAULT_LANG = "es"

STRINGS = {
    "es": {
        "lang_name": "Español",
        "report_title": "Reporte de seguridad",
        "generated_by": "Generado por SecScan Agent",
        "project": "Proyecto",
        "date": "Fecha",
        "duration": "Duración",
        "files_analyzed": "Archivos analizados",
        "skill": "Skill",
        "page": "Página",
        "of": "de",
        "seconds": "s",

        # Resumen ejecutivo
        "executive_summary": "Resumen ejecutivo",
        "risk_score": "Puntaje de riesgo",
        "risk_score_help": "0 = sin riesgo · 100 = riesgo máximo. Pondera severidad y confianza "
                           "de los hallazgos del código, dependencias y configuración.",
        "verdict": "Veredicto",
        "verdict_critical": "No apto para producción",
        "verdict_serious": "Requiere correcciones antes de desplegar",
        "verdict_warning": "Aceptable con observaciones",
        "verdict_good": "Sin riesgos relevantes detectados",
        "verdict_detail_critical": "Hay {n} hallazgos críticos que permiten comprometer el sistema. "
                                   "Deben corregirse antes de cualquier despliegue.",
        "verdict_detail_serious": "No hay hallazgos críticos, pero {n} de severidad alta deben "
                                  "corregirse antes de desplegar.",
        "verdict_detail_warning": "Solo se detectaron hallazgos de severidad media o baja. "
                                  "Planificar su corrección.",
        "verdict_detail_good": "El análisis no encontró vulnerabilidades en el alcance revisado.",
        "findings_total": "Hallazgos",
        "exposure_note": "Vulnerabilidades del proyecto",
        "threats_note": "Eventos de ataque en logs",

        "sev_CRITICA": "Crítica",
        "sev_ALTA": "Alta",
        "sev_MEDIA": "Media",
        "sev_BAJA": "Baja",
        "conf_ALTA": "Confianza alta",
        "conf_MEDIA": "Confianza media",
        "conf_BAJA": "Confianza baja",

        "severity_distribution": "Distribución por severidad",
        "priority_actions": "Acciones prioritarias",
        "priority_actions_help": "Hallazgos agrupados por la acción que los corrige, "
                                 "ordenados por severidad e impacto.",
        "col_action": "Acción",
        "col_findings": "Hallazgos",
        "col_files": "Archivos",
        "col_severity": "Severidad máx.",
        "col_sev": "Severidad",
        "col_effort": "Esfuerzo",
        "effort_low": "Bajo",
        "effort_medium": "Medio",
        "effort_high": "Alto",
        "owasp_chart": "Categorías OWASP Top 10",
        "files_chart": "Archivos más afectados",
        "no_data": "Sin datos",

        # Amenazas
        "threats": "Actividad de amenazas",
        "threats_help": "Indicios de ataque encontrados en los logs. No son vulnerabilidades del "
                        "código, pero indican que el sistema está siendo atacado.",
        "attack_events": "Eventos de ataque",
        "attacker_ips": "IPs atacantes",
        "active_attackers": "Atacantes activos",
        "active_attacker": "Atacante activo",
        "brute_force": "Fuerza bruta",
        "col_ip": "IP",
        "col_events": "Eventos",
        "col_attack_types": "Tipos de ataque",

        # Detalle
        "detailed_findings": "Hallazgos detallados",
        "search_placeholder": "Buscar por archivo, tipo o CWE…",
        "filter_all": "Todas",
        "filter_tool": "Herramienta",
        "all_tools": "Todas las herramientas",
        "showing": "Mostrando",
        "location": "Ubicación",
        "risk": "Riesgo",
        "fix": "Corrección",
        "detected_by": "Detectado por",
        "evidence": "Evidencia",
        "other_findings": "Otros hallazgos (severidad media y baja)",
        "log_events": "Eventos detectados en logs",
        "log_events_pdf_note": "Los eventos individuales de los logs se resumen en la sección "
                               "«Actividad de amenazas». El detalle completo está en los reportes HTML y JSON.",
        "col_type": "Tipo",
        "col_location": "Ubicación",
        "col_detail": "Detalle",
        "no_findings": "No se encontraron hallazgos.",

        # Anexo
        "agent_reasoning": "Razonamiento del agente",
        "agent_reasoning_help": "Cómo el agente decidió qué analizar: observó el proyecto, "
                                "razonó qué herramientas eran relevantes y las ejecutó en orden.",
        "phase_observe": "Observar",
        "phase_reason": "Razonar",
        "phase_act": "Actuar",
        "phase_report": "Reportar",
        "skipped_tools": "Herramientas omitidas por el skill",
        "status_success": "Completado",
        "status_error": "Error",
        "methodology": "Metodología",
        "methodology_text": "El puntaje de riesgo suma, por cada hallazgo del proyecto, un peso por "
                            "severidad (crítica 10, alta 5, media 2, baja 0,5) multiplicado por la "
                            "confianza (alta 1, media 0,75, baja 0,4), y lo normaliza a 0–100 con "
                            "100·(1 − e^(−puntos/60)). Los eventos de logs se informan aparte.",
        "toggle_theme": "Cambiar tema",
        "print": "Imprimir / PDF",
        "masked_note": "Los secretos se muestran enmascarados.",

        # Acciones
        "action_rotate_credentials": "Rotar y retirar credenciales expuestas",
        "action_rotate_credentials_why": "Cualquiera con acceso al código puede usarlas. Rotarlas "
                                         "en el proveedor y moverlas a un gestor de secretos.",
        "action_parametrize_sql": "Parametrizar las consultas SQL",
        "action_parametrize_sql_why": "Permiten leer, modificar o borrar la base de datos. Usar "
                                      "placeholders del driver o un ORM.",
        "action_update_dependencies": "Actualizar dependencias vulnerables",
        "action_update_dependencies_why": "Tienen CVE públicos y explotables. Subir a la versión "
                                          "corregida y fijar versiones.",
        "action_output_encoding": "Escapar la salida y eliminar plantillas dinámicas",
        "action_output_encoding_why": "Permiten XSS o ejecución de código en el servidor (SSTI). "
                                      "Usar plantillas con autoescape.",
        "action_harden_config": "Endurecer la configuración de producción",
        "action_harden_config_why": "Debug, CORS, SSL y logging inseguros facilitan otros "
                                    "ataques. Separar configuración por entorno.",
        "action_contain_threats": "Contener la actividad maliciosa detectada",
        "action_contain_threats_why": "Hay ataques en curso en los logs. Bloquear las IPs, revisar "
                                      "accesos exitosos y activar un WAF.",
        "action_other": "Revisar otros hallazgos",
        "action_other_why": "Hallazgos que no encajan en las categorías anteriores.",
    },
    "en": {
        "lang_name": "English",
        "report_title": "Security report",
        "generated_by": "Generated by SecScan Agent",
        "project": "Project",
        "date": "Date",
        "duration": "Duration",
        "files_analyzed": "Files analyzed",
        "skill": "Skill",
        "page": "Page",
        "of": "of",
        "seconds": "s",

        "executive_summary": "Executive summary",
        "risk_score": "Risk score",
        "risk_score_help": "0 = no risk · 100 = maximum risk. Weighs severity and confidence of "
                           "code, dependency and configuration findings.",
        "verdict": "Verdict",
        "verdict_critical": "Not fit for production",
        "verdict_serious": "Fixes required before deploying",
        "verdict_warning": "Acceptable with observations",
        "verdict_good": "No relevant risks detected",
        "verdict_detail_critical": "{n} critical findings allow the system to be compromised. "
                                   "They must be fixed before any deployment.",
        "verdict_detail_serious": "No critical findings, but {n} high-severity findings must be "
                                  "fixed before deploying.",
        "verdict_detail_warning": "Only medium or low severity findings were detected. "
                                  "Plan their remediation.",
        "verdict_detail_good": "The analysis found no vulnerabilities in the reviewed scope.",
        "findings_total": "Findings",
        "exposure_note": "Project vulnerabilities",
        "threats_note": "Attack events in logs",

        "sev_CRITICA": "Critical",
        "sev_ALTA": "High",
        "sev_MEDIA": "Medium",
        "sev_BAJA": "Low",
        "conf_ALTA": "High confidence",
        "conf_MEDIA": "Medium confidence",
        "conf_BAJA": "Low confidence",

        "severity_distribution": "Severity distribution",
        "priority_actions": "Priority actions",
        "priority_actions_help": "Findings grouped by the action that fixes them, "
                                 "ordered by severity and impact.",
        "col_action": "Action",
        "col_findings": "Findings",
        "col_files": "Files",
        "col_severity": "Max. severity",
        "col_sev": "Severity",
        "col_effort": "Effort",
        "effort_low": "Low",
        "effort_medium": "Medium",
        "effort_high": "High",
        "owasp_chart": "OWASP Top 10 categories",
        "files_chart": "Most affected files",
        "no_data": "No data",

        "threats": "Threat activity",
        "threats_help": "Attack indicators found in the logs. They are not code vulnerabilities, "
                        "but they show the system is being targeted.",
        "attack_events": "Attack events",
        "attacker_ips": "Attacker IPs",
        "active_attackers": "Active attackers",
        "active_attacker": "Active attacker",
        "brute_force": "Brute force",
        "col_ip": "IP",
        "col_events": "Events",
        "col_attack_types": "Attack types",

        "detailed_findings": "Detailed findings",
        "search_placeholder": "Search by file, type or CWE…",
        "filter_all": "All",
        "filter_tool": "Tool",
        "all_tools": "All tools",
        "showing": "Showing",
        "location": "Location",
        "risk": "Risk",
        "fix": "Fix",
        "detected_by": "Detected by",
        "evidence": "Evidence",
        "other_findings": "Other findings (medium and low severity)",
        "log_events": "Events detected in logs",
        "log_events_pdf_note": "Individual log events are summarized in the «Threat activity» "
                               "section. Full detail is available in the HTML and JSON reports.",
        "col_type": "Type",
        "col_location": "Location",
        "col_detail": "Detail",
        "no_findings": "No findings were detected.",

        "agent_reasoning": "Agent reasoning",
        "agent_reasoning_help": "How the agent decided what to analyze: it observed the project, "
                                "reasoned which tools were relevant and ran them in order.",
        "phase_observe": "Observe",
        "phase_reason": "Reason",
        "phase_act": "Act",
        "phase_report": "Report",
        "skipped_tools": "Tools skipped by the skill",
        "status_success": "Completed",
        "status_error": "Error",
        "methodology": "Methodology",
        "methodology_text": "For each project finding, the risk score adds a severity weight "
                            "(critical 10, high 5, medium 2, low 0.5) multiplied by confidence "
                            "(high 1, medium 0.75, low 0.4), normalized to 0–100 with "
                            "100·(1 − e^(−points/60)). Log events are reported separately.",
        "toggle_theme": "Toggle theme",
        "print": "Print / PDF",
        "masked_note": "Secrets are shown masked.",

        "action_rotate_credentials": "Rotate and remove exposed credentials",
        "action_rotate_credentials_why": "Anyone with code access can use them. Rotate them at the "
                                         "provider and move them to a secrets manager.",
        "action_parametrize_sql": "Parameterize SQL queries",
        "action_parametrize_sql_why": "They allow reading, modifying or deleting the database. Use "
                                      "driver placeholders or an ORM.",
        "action_update_dependencies": "Update vulnerable dependencies",
        "action_update_dependencies_why": "They have public, exploitable CVEs. Upgrade to the fixed "
                                          "version and pin versions.",
        "action_output_encoding": "Escape output and remove dynamic templates",
        "action_output_encoding_why": "They allow XSS or server-side code execution (SSTI). Use "
                                      "templates with autoescape.",
        "action_harden_config": "Harden the production configuration",
        "action_harden_config_why": "Insecure debug, CORS, SSL and logging settings enable other "
                                    "attacks. Split configuration per environment.",
        "action_contain_threats": "Contain the detected malicious activity",
        "action_contain_threats_why": "Attacks are under way in the logs. Block the IPs, review "
                                      "successful accesses and enable a WAF.",
        "action_other": "Review other findings",
        "action_other_why": "Findings that do not fit the categories above.",
    },
}

SUPPORTED_LANGS = tuple(STRINGS)


class Translator:
    """Acceso a los textos de un idioma, con respaldo al idioma por defecto."""

    def __init__(self, lang: str = DEFAULT_LANG):
        self.lang = lang if lang in STRINGS else DEFAULT_LANG

    def __call__(self, key: str, **kwargs) -> str:
        text = STRINGS[self.lang].get(key) or STRINGS[DEFAULT_LANG].get(key, key)
        return text.format(**kwargs) if kwargs else text
