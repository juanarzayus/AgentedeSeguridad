"""Pruebas de la interfaz web: flujo completo y, sobre todo, sus controles de seguridad."""

import json
import os
import re
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    from webapp.server import COOKIE, create_app
except ImportError:  # Flask no instalado
    create_app = None

TEST_PROJECT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "test_project"))
PORT = 8765
HOST = f"127.0.0.1:{PORT}"


@unittest.skipIf(create_app is None, "Flask no está instalado")
class TestWebApp(unittest.TestCase):
    def setUp(self):
        self.out = tempfile.mkdtemp()
        self.app = create_app(port=PORT, output_dir=self.out)
        self.token = self.app.config["SECSCAN_TOKEN"]
        self.client = self.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.out, ignore_errors=True)

    def get(self, path, **kw):
        return self.client.get(path, base_url=f"http://{HOST}", **kw)

    def login(self):
        r = self.get(f"/?token={self.token}")
        self.assertEqual(r.status_code, 303)
        page = self.get("/").get_data(as_text=True)
        return re.search(r'name="csrf-token" content="([^"]+)"', page).group(1)

    def post_scan(self, csrf, **payload):
        body = {"target": TEST_PROJECT, "skill": "quick_scan", "lang": "es", **payload}
        return self.client.post("/api/scans", base_url=f"http://{HOST}", data=json.dumps(body),
                                content_type="application/json", headers={"X-CSRF-Token": csrf})

    def wait(self, scan_id, timeout=30):
        deadline = time.time() + timeout
        while time.time() < deadline:
            data = self.get(f"/api/scans/{scan_id}").get_json()
            if data["status"] in ("done", "error"):
                return data
            time.sleep(0.1)
        self.fail("el análisis no terminó a tiempo")

    # ── Seguridad ──

    def test_requires_session(self):
        self.assertEqual(self.get("/").status_code, 401)
        self.assertEqual(self.get("/api/scans").status_code, 401)
        self.assertEqual(self.get("/?token=incorrecto").status_code, 401)

    def test_rejects_foreign_host(self):
        """Protección contra DNS rebinding: solo se aceptan 127.0.0.1/localhost."""
        r = self.client.get(f"/?token={self.token}", base_url="http://evil.example:8765")
        self.assertEqual(r.status_code, 400)

    def test_session_cookie_is_hardened(self):
        r = self.get(f"/?token={self.token}")
        cookie = r.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertEqual(r.headers["Location"], "/")  # el token sale de la URL

    def test_post_requires_csrf(self):
        self.login()
        r = self.client.post("/api/scans", base_url=f"http://{HOST}", json={"target": TEST_PROJECT,
                             "skill": "quick_scan", "lang": "es"})
        self.assertEqual(r.status_code, 403)

    def test_security_headers(self):
        self.login()
        r = self.get("/")
        csp = r.headers["Content-Security-Policy"]
        self.assertIn("script-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(r.headers["Cache-Control"], "no-store")

    def test_input_validation(self):
        csrf = self.login()
        self.assertEqual(self.post_scan(csrf, target="/no/existe").get_json()["error"], "not_a_directory")
        self.assertEqual(self.post_scan(csrf, target="").get_json()["error"], "missing")
        self.assertEqual(self.post_scan(csrf, skill="../../etc").status_code, 400)
        self.assertEqual(self.post_scan(csrf, lang="fr").status_code, 400)
        self.assertEqual(self.post_scan(csrf, target=["x"]).status_code, 400)

    def test_browser_lists_only_directories(self):
        self.login()
        data = self.get(f"/api/fs?path={TEST_PROJECT}").get_json()
        self.assertIn("logs", data["dirs"])
        self.assertNotIn("app.py", data["dirs"])  # nunca archivos

    def test_fonts_whitelist(self):
        self.assertEqual(self.get("/fonts/inter-400.woff2").status_code, 200)
        self.assertEqual(self.get("/fonts/..%2F..%2Fhtml_report.py").status_code, 404)

    # ── Flujo completo ──

    def test_scan_flow_and_downloads(self):
        csrf = self.login()
        r = self.post_scan(csrf, logs=os.path.join(TEST_PROJECT, "logs"), skill="full_security_review")
        self.assertEqual(r.status_code, 202)
        scan_id = r.get_json()["id"]

        data = self.wait(scan_id)
        self.assertEqual(data["status"], "done")
        types = [e["type"] for e in data["events"]]
        for kind in ("phase", "context", "plan", "step_start", "step_end", "done"):
            self.assertIn(kind, types)
        self.assertGreater(data["summary"]["risk_score"], 50)

        report = self.get(f"/scans/{scan_id}/report")
        self.assertEqual(report.status_code, 200)
        self.assertTrue(report.headers["Content-Security-Policy"].startswith("sandbox"))

        exported = self.get(f"/scans/{scan_id}/download/json")
        self.assertIn("attachment", exported.headers["Content-Disposition"])
        self.assertNotRegex(exported.get_data(as_text=True), r"AKIA[A-Z0-9]{16}")

        self.assertEqual(self.get(f"/scans/{scan_id}/download/py").status_code, 404)
        self.assertEqual(self.get("/scans/no-existe/report").status_code, 404)

    def test_one_scan_at_a_time(self):
        csrf = self.login()
        first = self.post_scan(csrf).get_json()["id"]
        second = self.post_scan(csrf)
        if second.status_code == 202:  # el primero terminó antes de tiempo
            self.wait(second.get_json()["id"])
        else:
            self.assertEqual(second.status_code, 409)
        self.wait(first)


if __name__ == "__main__":
    unittest.main()
