"""
SecScan Web — Interfaz gráfica local para operar el agente.

Modelo de amenazas: la interfaz corre en el equipo del usuario y puede leer
cualquier directorio que él indique. Por eso NO debe ser accesible por nadie más:

1. Escucha solo en 127.0.0.1 (no hay opción para exponerla a la red).
2. Valida el encabezado Host → bloquea DNS rebinding desde sitios maliciosos.
3. Token de sesión aleatorio (como Jupyter): la terminal muestra un enlace con el
   token; el navegador lo cambia por una cookie HttpOnly + SameSite=Strict.
   Sin esa cookie ninguna ruta responde (protege de otros usuarios/procesos locales).
4. CSRF: toda petición POST exige el encabezado X-CSRF-Token.
5. CSP estricta (sin scripts inline), frame-ancestors 'none', nosniff, no-store.
6. Los reportes se sirven con `CSP: sandbox` → su JavaScript corre en un origen
   opaco y no puede llamar a la API.
7. Las descargas se identifican por ID de análisis, nunca por ruta.
8. Errores genéricos: nunca se envían trazas al navegador.
"""

from __future__ import annotations

import hmac
import os
import secrets
import webbrowser
from functools import wraps

from flask import Flask, Response, abort, jsonify, make_response, redirect, render_template, request, send_file

from report.html_report import ASSETS, icon
from report.i18n import SUPPORTED_LANGS
from skills.security_review import SecurityReviewSkill
from webapp.i18n import UI_STRINGS
from webapp.scans import DOWNLOAD_FORMATS, PdfUnavailableError, ScanManager

HOST = "127.0.0.1"
DEFAULT_PORT = 8765
COOKIE = "secscan_session"
FONT_FILES = {"inter-400.woff2", "inter-500.woff2", "inter-600.woff2", "inter-700.woff2",
              "jbm-400.woff2", "jbm-600.woff2"}
MAX_DIR_ENTRIES = 300

APP_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
           "font-src 'self'; connect-src 'self'; frame-src 'self'; frame-ancestors 'none'; "
           "base-uri 'none'; form-action 'none'")
# El reporte trae su CSS/JS en línea: se permite, pero aislado en un sandbox sin origen
REPORT_CSP = ("sandbox allow-scripts allow-modals allow-popups; default-src 'none'; "
              "style-src 'unsafe-inline'; script-src 'unsafe-inline'; font-src data:; img-src data:; "
              "frame-ancestors 'self'")


def create_app(port: int = DEFAULT_PORT, output_dir: str = "reports/web") -> Flask:
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config.update(
        MAX_CONTENT_LENGTH=16 * 1024,  # solo se reciben JSON pequeños
        JSON_SORT_KEYS=False,
        PROPAGATE_EXCEPTIONS=False,
    )
    app.jinja_env.globals["icon"] = icon

    session_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    allowed_hosts = {f"{HOST}:{port}", f"localhost:{port}"}
    manager = ScanManager(os.path.abspath(output_dir))
    app.config["SECSCAN_TOKEN"] = session_token
    app.config["SECSCAN_URL"] = f"http://{HOST}:{port}/?token={session_token}"

    # ═══════════ Capa de seguridad ═══════════

    def _valid(token: str | None, expected: str) -> bool:
        return bool(token) and hmac.compare_digest(token, expected)

    @app.before_request
    def guard():
        if request.host not in allowed_hosts:
            abort(400)  # DNS rebinding u otro host
        if request.path == "/" and _valid(request.args.get("token"), session_token):
            response = redirect("/", code=303)  # quitar el token de la URL y del historial
            response.set_cookie(COOKIE, session_token, httponly=True, samesite="Strict",
                                secure=False, path="/")
            return response
        if request.path.startswith(("/static/", "/fonts/")) and request.method == "GET":
            return None  # CSS/JS/fuentes públicos: no contienen datos (la página de bloqueo los usa)
        if not _valid(request.cookies.get(COOKIE), session_token):
            return make_response(render_template("locked.html.j2"), 401)
        if request.method not in ("GET", "HEAD") and not _valid(request.headers.get("X-CSRF-Token"), csrf_token):
            abort(403)

    @app.after_request
    def headers(response):
        response.headers.setdefault("Content-Security-Policy", APP_CSP)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cache-Control"] = "no-store"
        response.headers.pop("Server", None)
        return response

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(405)
    @app.errorhandler(413)
    @app.errorhandler(500)
    def error(e):
        code = getattr(e, "code", 500)
        if request.path.startswith("/api/"):
            return jsonify({"error": "request_rejected", "status": code}), code
        return Response(str(code), status=code, content_type="text/plain; charset=utf-8")

    def json_body(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            data = request.get_json(silent=True)
            if not isinstance(data, dict):
                abort(400)
            return f(data, *args, **kwargs)
        return wrapper

    # ═══════════ Páginas ═══════════

    @app.get("/")
    def index():
        skills = [{"key": k, "name": v["name"], "description": v["description"], "tools": v["tools_used"]}
                  for k, v in SecurityReviewSkill.SKILL_DEFINITIONS.items()]
        return render_template("index.html.j2", csrf_token=csrf_token, skills=skills,
                               langs=SUPPORTED_LANGS, strings=UI_STRINGS, home=os.path.expanduser("~"),
                               cwd=os.getcwd())

    @app.get("/fonts/<name>")
    def fonts(name):
        if name not in FONT_FILES:  # lista blanca: nada de rutas arbitrarias
            abort(404)
        response = send_file(os.path.join(ASSETS, "fonts", name), mimetype="font/woff2")
        response.headers["Cache-Control"] = "private, max-age=86400"
        return response

    # ═══════════ API ═══════════

    def _directory(path: str | None, required: bool) -> str | None:
        if not path:
            if required:
                raise ValueError("missing")
            return None
        if not isinstance(path, str) or len(path) > 4096 or "\x00" in path:
            raise ValueError("invalid")
        real = os.path.realpath(os.path.expanduser(path))
        if not os.path.isdir(real):
            raise ValueError("not_a_directory")
        return real

    @app.post("/api/scans")
    @json_body
    def start_scan(data):
        try:
            target = _directory(data.get("target"), required=True)
            logs = _directory(data.get("logs"), required=False)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        skill = data.get("skill")
        lang = data.get("lang")
        if skill not in SecurityReviewSkill.SKILL_DEFINITIONS or lang not in SUPPORTED_LANGS:
            return jsonify({"error": "invalid"}), 400
        try:
            scan = manager.start(target, logs, skill, lang)
        except RuntimeError:
            return jsonify({"error": "busy"}), 409
        return jsonify({"id": scan.id}), 202

    @app.get("/api/scans")
    def list_scans():
        return jsonify({"scans": manager.history(), "busy": manager.busy})

    @app.get("/api/scans/<scan_id>")
    def scan_status(scan_id):
        scan = manager.get(scan_id)
        if scan is None:
            abort(404)
        since = request.args.get("since", default=0, type=int)
        return jsonify(scan.snapshot(max(0, since)))

    @app.get("/api/fs")
    def browse():
        """Lista SOLO subdirectorios (nunca archivos) para elegir la carpeta a analizar."""
        try:
            path = _directory(request.args.get("path") or os.path.expanduser("~"), required=True)
        except ValueError:
            return jsonify({"error": "not_a_directory"}), 400
        try:
            entries = sorted(
                (e.name for e in os.scandir(path)
                 if e.is_dir(follow_symlinks=False) and not e.name.startswith(".")),
                key=str.lower,
            )[:MAX_DIR_ENTRIES]
        except OSError:
            return jsonify({"error": "unreadable"}), 400
        parent = os.path.dirname(path)
        return jsonify({"path": path, "parent": parent if parent != path else None, "dirs": entries})

    # ═══════════ Reportes ═══════════

    def _scan_file(scan_id: str, fmt: str) -> str:
        scan = manager.get(scan_id)
        if scan is None or fmt not in DOWNLOAD_FORMATS:
            abort(404)
        try:
            return manager.report_file(scan, fmt)
        except ValueError:
            abort(404)

    @app.get("/scans/<scan_id>/report")
    def view_report(scan_id):
        response = send_file(_scan_file(scan_id, "html"), mimetype="text/html")
        response.headers["Content-Security-Policy"] = REPORT_CSP
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        return response

    @app.get("/scans/<scan_id>/download/<fmt>")
    def download(scan_id, fmt):
        try:
            path = _scan_file(scan_id, fmt)
        except PdfUnavailableError:
            return jsonify({"error": "pdf_unavailable"}), 503
        mimetypes = {"html": "text/html", "pdf": "application/pdf", "json": "application/json"}
        response = send_file(path, mimetype=mimetypes[fmt], as_attachment=True,
                             download_name=f"secscan-{scan_id[:8]}.{fmt}")
        if fmt == "html":
            response.headers["Content-Security-Policy"] = REPORT_CSP
        return response

    return app


def serve(port: int = DEFAULT_PORT, open_browser: bool = True, output_dir: str = "reports/web"):
    """Arranca el servidor de producción (Waitress) solo en 127.0.0.1."""
    from waitress import serve as waitress_serve
    from agent.ui import console

    app = create_app(port=port, output_dir=output_dir)
    url = app.config["SECSCAN_URL"]
    console.print()
    console.print("[bold]SecScan Web[/]  [dim]interfaz local[/]")
    console.print(f"  Abrir: [bold underline]{url}[/]")
    console.print("  [dim]Solo accesible desde este equipo. El enlace incluye un token de sesión:\n"
                  "  no lo compartas. Ctrl+C para detener.[/]\n")
    if open_browser:
        webbrowser.open(url)
    waitress_serve(app, host=HOST, port=port, threads=4, ident=None, clear_untrusted_proxy_headers=True)
