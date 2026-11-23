"""
Pruebas unitarias para SecScan Agent.
Verifica el funcionamiento de los Tools, el Planner y el Orchestrator.
"""

import io
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agent.planner import Planner, ScanContext
from agent.tool_registry import ToolRegistry, ToolDefinition
from agent.orchestrator import SecScanOrchestrator
from tools.secret_scanner import scan_secrets
from tools.sqli_detector import detect_sqli
from tools.xss_detector import detect_xss
from tools.dependency_audit import audit_dependencies
from tools.config_auditor import audit_config
from tools.log_analyzer import analyze_logs


class TestToolRegistry(unittest.TestCase):
    def setUp(self):
        self.registry = ToolRegistry()

    def test_register_and_get_tool(self):
        tool = ToolDefinition(
            name="test_tool",
            description="Herramienta de prueba",
            category="test",
            execute=lambda x: x * 2,
            parameters={"x": "int"}
        )
        self.registry.register(tool)
        self.assertEqual(self.registry.tool_count, 1)
        self.assertIsNotNone(self.registry.get("test_tool"))
        self.assertEqual(self.registry.execute_tool("test_tool", x=5), 10)

    def test_execute_nonexistent_tool(self):
        with self.assertRaises(ValueError):
            self.registry.execute_tool("unknown_tool")


class TestSecurityTools(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_secret_scanner(self):
        secret_file = os.path.join(self.test_dir, "secrets.py")
        with open(secret_file, "w", encoding="utf-8") as f:
            f.write('AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"\n')
            f.write('API_KEY = "sk-live-123456789012345678901234567890"\n')
            f.write('password = "SuperSecretPassword123!"\n')

        findings = scan_secrets([secret_file])
        self.assertGreaterEqual(len(findings), 2)
        severities = [f["severity"] for f in findings]
        self.assertIn("CRITICA", severities)

    def test_sqli_detector(self):
        sqli_file = os.path.join(self.test_dir, "db.py")
        with open(sqli_file, "w", encoding="utf-8") as f:
            f.write('cursor.execute("SELECT * FROM users WHERE id = \'" + user_id + "\'")\n')
            f.write('cursor.execute(f"SELECT * FROM items WHERE name = \'{item_name}\'")\n')

        findings = detect_sqli([sqli_file])
        self.assertGreaterEqual(len(findings), 2)
        types = [f["type"] for f in findings]
        self.assertTrue(any("Concatenación" in t or "f-string" in t for t in types))

    def test_xss_detector(self):
        xss_file = os.path.join(self.test_dir, "view.py")
        with open(xss_file, "w", encoding="utf-8") as f:
            f.write('return render_template_string(f"<h1>{user_input}</h1>")\n')
            f.write('element.innerHTML = user_data;\n')

        findings = detect_xss([xss_file])
        self.assertGreaterEqual(len(findings), 1)

    def test_dependency_audit(self):
        req_file = os.path.join(self.test_dir, "requirements.txt")
        with open(req_file, "w", encoding="utf-8") as f:
            f.write('flask==2.2.0\n')
            f.write('requests==2.28.0\n')

        findings = audit_dependencies([req_file])
        self.assertGreaterEqual(len(findings), 1)
        self.assertTrue(any("CVE" in f["type"] for f in findings))

    def test_config_auditor(self):
        conf_file = os.path.join(self.test_dir, "config.py")
        with open(conf_file, "w", encoding="utf-8") as f:
            f.write('DEBUG = True\n')
            f.write('SECRET_KEY = "change-me"\n')
            f.write('CORS_ORIGIN_ALLOW_ALL = True\n')

        findings = audit_config([conf_file])
        self.assertGreaterEqual(len(findings), 2)


class TestPlannerAndOrchestrator(unittest.TestCase):
    def test_planner_reasoning(self):
        planner = Planner()
        # Analizamos el proyecto de prueba incluido
        test_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "test_project"))
        logs_path = os.path.join(test_path, "logs")

        ctx = planner.analyze_context(test_path, logs_path)
        self.assertTrue(ctx.has_python_files)
        self.assertTrue(ctx.has_requirements)
        self.assertTrue(ctx.has_config_files)
        self.assertTrue(ctx.has_log_files)

        plan = planner.create_plan(ctx)
        self.assertGreaterEqual(len(plan.steps), 4)

        # Verificar que el plan incluye justificación/razonamiento en cada paso
        for step in plan.steps:
            self.assertIn("tool", step)
            self.assertIn("reason", step)
            self.assertGreater(len(step["reason"]), 10)

    def test_orchestrator_end_to_end(self):
        orchestrator = SecScanOrchestrator(verbose=False)
        test_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "test_project"))
        logs_path = os.path.join(test_path, "logs")

        results = orchestrator.run(test_path, logs_path)
        self.assertIn("total_findings", results)
        self.assertGreater(results["total_findings"], 20)
        self.assertIn("CRITICA", results["severity_counts"])


# ════════════════════════════════════════════════════════════
# Regresiones: errores corregidos
# ════════════════════════════════════════════════════════════

TEST_PROJECT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "test_project"))
REPO_ROOT = os.path.dirname(TEST_PROJECT)


def _write(directory, name, content):
    path = os.path.join(directory, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


class TempDirTestCase(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)


class TestSkills(TempDirTestCase):
    """Bug 1: los skills deben limitar las herramientas ejecutadas."""

    def _run_skill(self, skill):
        from skills.security_review import SecurityReviewSkill
        out = os.path.join(self.test_dir, "reports")
        return SecurityReviewSkill(verbose=False).execute(
            skill, TEST_PROJECT, os.path.join(TEST_PROJECT, "logs"), "json", out)

    def test_quick_scan_only_runs_its_tools(self):
        results = self._run_skill("quick_scan")
        executed = {e["tool"] for e in results["execution_log"]}
        self.assertEqual(executed, {"secret_scanner", "sqli_detector"})
        self.assertIn("dependency_audit", results["plan"]["skipped_tools"])

    def test_dependency_check_only_runs_dependency_audit(self):
        results = self._run_skill("dependency_check")
        self.assertEqual({e["tool"] for e in results["execution_log"]}, {"dependency_audit"})
        self.assertTrue(all(f["tool"] == "DependencyAudit" for f in results["findings"]))

    def test_full_review_runs_everything_including_xss_on_python(self):
        results = self._run_skill("full_security_review")
        executed = {e["tool"] for e in results["execution_log"]}
        self.assertIn("xss_detector", executed)  # el proyecto de prueba solo tiene .py
        self.assertEqual(len(executed), 6)


class TestSecretMasking(TempDirTestCase):
    """Bug 2: ningún secreto puede llegar en claro al reporte."""

    SECRETS = [
        "P@ssw0rd2024!",
        "sk-live-4eC39HqLyjWDarjtT1zdp7dc",
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
    ]

    def test_scanner_masks_content_and_matched_value(self):
        path = _write(self.test_dir, "settings.py",
                      f'password = "{self.SECRETS[0]}"\n'
                      f'API_KEY = "{self.SECRETS[1]}"; token = "{self.SECRETS[2]}"\n')
        findings = scan_secrets([path])
        self.assertGreaterEqual(len(findings), 3)
        dumped = repr(findings)
        for secret in self.SECRETS:
            self.assertNotIn(secret, dumped)

    def test_config_auditor_masks_db_password(self):
        path = _write(self.test_dir, "config.py", 'DB_PASSWORD = "P@ssw0rd2024!"\n')
        findings = audit_config([path])
        self.assertEqual(len(findings), 1)
        self.assertNotIn("P@ssw0rd2024!", repr(findings))

    def test_reports_do_not_contain_secrets(self):
        from report.generator import ReportGenerator
        results = SecScanOrchestrator(verbose=False).run(TEST_PROJECT)
        out = os.path.join(self.test_dir, "out")
        for fmt in ("json", "html"):
            path = ReportGenerator().generate(results, format=fmt, output_dir=out)
            with open(path, encoding="utf-8") as f:
                text = f.read()
            for secret in ("P@ssw0rd2024!", "MyDatabaseP@ssw0rd!", "sk-live-4eC39HqLyjWDarjtT1zdp7dc",
                           "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "SuperSecret123!"):
                self.assertNotIn(secret, text, f"{secret} filtrado en reporte {fmt}")


class TestRequirementsFile(unittest.TestCase):
    """Bug 3: toda dependencia importada debe estar declarada."""

    def test_packaging_declared(self):
        with open(os.path.join(REPO_ROOT, "requirements.txt"), encoding="utf-8") as f:
            names = {l.split(">")[0].split("=")[0].strip().lower() for l in f if l.strip()}
        self.assertIn("packaging", names)


class TestHtmlEscaping(TempDirTestCase):
    """Bug 4: el reporte HTML no puede ejecutar contenido del proyecto analizado."""

    def test_malicious_filename_and_content_are_escaped(self):
        from report.generator import ReportGenerator
        payload = "<img src=x onerror=alert(1)>"
        results = {
            "target": payload,
            "total_findings": 1,
            "severity_counts": {"ALTA": 1},
            "findings": [{
                "tool": "XSSDetector", "file": f"/tmp/{payload}.py", "line": 1,
                "content": payload, "type": payload, "severity": "ALTA",
                "description": payload, "recommendation": payload,
            }],
            "plan": {"steps": [{"order": 1, "tool": payload, "reason": payload}]},
            "execution_log": [{"step": 1, "tool": payload, "status": "error", "error": payload}],
        }
        path = ReportGenerator().generate(results, format="html", output_dir=self.test_dir)
        with open(path, encoding="utf-8") as f:
            html_text = f.read()
        self.assertNotIn(payload, html_text)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", html_text)


class TestDependencyVersions(TempDirTestCase):
    """Bug 5: interpretación correcta de versiones y rangos."""

    def _audit(self, content, name="requirements.txt"):
        return audit_dependencies([_write(self.test_dir, name, content)])

    def test_exact_vulnerable_version(self):
        findings = self._audit("flask==2.2.0\n")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "ALTA")
        self.assertEqual(findings[0]["line"], 1)

    def test_exact_fixed_version_is_clean(self):
        self.assertEqual(self._audit("flask==3.0.0\n"), [])

    def test_lower_bound_already_fixed_is_clean(self):
        self.assertEqual(self._audit("flask>=2.3.2\n"), [])

    def test_permissive_range_is_low_severity(self):
        findings = self._audit("flask>=2.0\n")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "BAJA")
        self.assertIn("rango permisivo", findings[0]["type"])

    def test_upper_bounded_range_is_vulnerable(self):
        findings = self._audit("flask>=2.0,<2.3\n")
        self.assertEqual(findings[0]["severity"], "ALTA")

    def test_unpinned_is_low_not_every_cve(self):
        findings = self._audit("django\n")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "BAJA")

    def test_name_normalization_and_comments(self):
        findings = self._audit("# comentario\nFlask==2.2.0  # viejo\nJinja2==3.1.0\n")
        self.assertEqual({f["line"] for f in findings}, {2, 3})

    def test_package_json_caret_range(self):
        findings = self._audit('{"dependencies": {"lodash": "^4.17.21", "axios": "1.5.0"}}',
                               name="package.json")
        self.assertEqual([f["content"] for f in findings], ["axios==1.5.0"])

    def test_no_placeholder_cves(self):
        from tools.dependency_audit import VULNERABILITY_DB
        for vulns in VULNERABILITY_DB.values():
            for v in vulns:
                self.assertRegex(v["cve"], r"^CVE-\d{4}-\d{4,}$")


class TestDeduplication(TempDirTestCase):
    """Bug 6: un mismo problema no debe reportarse dos veces."""

    def test_cross_tool_duplicates_are_merged(self):
        _write(self.test_dir, "config.py", 'DB_PASSWORD = "P@ssw0rd2024!"\n')
        results = SecScanOrchestrator(verbose=False).run(self.test_dir)
        self.assertEqual(results["total_findings"], 1)
        finding = results["findings"][0]
        self.assertEqual(finding["severity"], "CRITICA")
        self.assertTrue(finding["also_detected_by"])

    def test_sqli_reported_once_on_the_right_line(self):
        path = _write(self.test_dir, "db.py",
                      "def f(cursor, name):\n"
                      "    x = 1\n"
                      "    cursor.execute(f\"SELECT * FROM t WHERE n = '{name}'\")\n")
        findings = detect_sqli([path])
        self.assertEqual([f["line"] for f in findings], [3])

    def test_logs_inside_target_are_analyzed_once(self):
        planner = Planner()
        ctx = planner.analyze_context(TEST_PROJECT, os.path.join(TEST_PROJECT, "logs"))
        resolved = [os.path.realpath(f) for f in ctx.file_list]
        self.assertEqual(len(resolved), len(set(resolved)))
        self.assertEqual(len(ctx.log_file_list), 1)


class TestLogsPathResolution(unittest.TestCase):
    """Bug 7: --logs funciona con rutas relativas y absolutas."""

    def test_relative_logs_path(self):
        cwd = os.getcwd()
        try:
            os.chdir(TEST_PROJECT)
            ctx = Planner().analyze_context(".", "./logs/")
            plan = Planner().create_plan(ctx)
        finally:
            os.chdir(cwd)
        self.assertIn("log_analyzer", [s["tool"] for s in plan.steps])

    def test_no_logs_flag_means_no_log_analysis(self):
        plan = Planner().create_plan(Planner().analyze_context(TEST_PROJECT))
        self.assertNotIn("log_analyzer", [s["tool"] for s in plan.steps])


class TestExitCodes(TempDirTestCase):
    """Bug 7: los códigos de salida no se pisan entre 'error' y 'hallazgos'."""

    def _main(self, *argv):
        import main
        old = sys.argv
        sys.argv = ["main.py", "-q", "-o", self.test_dir, *argv]
        try:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                try:
                    return main.main()
                except SystemExit as e:
                    return e.code
        finally:
            sys.argv = old

    def test_clean_project(self):
        _write(self.test_dir, "src/ok.py", "print('hola')\n")
        self.assertEqual(self._main("-t", os.path.join(self.test_dir, "src"), "-f", "json"), 0)

    def test_critical_findings(self):
        self.assertEqual(self._main("-t", TEST_PROJECT, "-f", "json"), 2)

    def test_missing_directory_is_error(self):
        self.assertEqual(self._main("-t", "/no/existe"), 3)

    def test_bad_argument_is_error_not_critical(self):
        self.assertEqual(self._main("-t", TEST_PROJECT, "--format", "docx"), 3)


# ════════════════════════════════════════════════════════════
# Mejoras de calidad: falsos positivos
# ════════════════════════════════════════════════════════════

class TestFalsePositives(TempDirTestCase):
    """Código seguro que NO debe generar hallazgos."""

    def test_parameterized_and_non_sql_strings(self):
        path = _write(self.test_dir, "safe.py",
                      "def f(cursor, name, n):\n"
                      "    cursor.execute('SELECT * FROM users WHERE name = ?', (name,))\n"
                      "    cursor.execute('UPDATE t SET a = %s WHERE id = %s', (n, name))\n"
                      "    print(f'Selected {n} items from the list')\n"
                      "    log.query(f'user {name} logged in')\n")
        self.assertEqual(detect_sqli([path]), [])

    def test_secret_placeholders_and_env_reads(self):
        path = _write(self.test_dir, "settings.py",
                      'API_KEY = os.getenv("API_KEY")\n'
                      'password = "changeme"\n'
                      'password = "********"\n'
                      'api_key = "your_api_key_here"\n'
                      'token = "xxxxxxxxxxxxxxxxxxxxxxxx"\n'
                      'api_key = "${API_KEY_FROM_ENVIRONMENT}"\n'
                      'api_key = "aaaaaaaaaaaaaaaaaaaaaaaa"\n')
        self.assertEqual(scan_secrets([path]), [])

    def test_real_secrets_still_detected(self):
        path = _write(self.test_dir, "settings.py",
                      'api_key = "sk-proj-abc123def456ghi789jkl012"\n'
                      "app.config['SECRET_KEY'] = 'mysecretkey123'\n")
        self.assertEqual({f["line"] for f in scan_secrets([path])}, {1, 2})


class TestSqliAst(TempDirTestCase):
    def test_variable_flow_and_user_input(self):
        path = _write(self.test_dir, "views.py",
                      "from flask import request\n"
                      "def view(cursor):\n"
                      "    uid = request.args.get('id')\n"
                      "    q = 'SELECT * FROM t WHERE id = ' + uid\n"
                      "    cursor.execute(q)\n")
        findings = detect_sqli([path])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["line"], 5)
        self.assertIn("input del usuario", findings[0]["type"])
        self.assertEqual(findings[0]["confidence"], "ALTA")
        self.assertEqual(findings[0]["cwe"], "CWE-89")

    def test_invalid_python_falls_back_to_regex(self):
        path = _write(self.test_dir, "py2.py",
                      'print "hola"\n'
                      'cursor.execute("SELECT * FROM t WHERE id = " + uid)\n')
        self.assertEqual(len(detect_sqli([path])), 1)


class TestSuppressions(TempDirTestCase):
    def test_inline_comment(self):
        _write(self.test_dir, "a.py",
               'password = "SuperSecretPassword123!"  # secscan: ignore\n'
               'token = "abcdefghijklmnopqrstuvwxyz0123"  # nosec\n')
        results = SecScanOrchestrator(verbose=False).run(self.test_dir)
        self.assertEqual(results["total_findings"], 0)
        self.assertEqual(results["suppressed_count"], 2)

    def test_secscanignore_file(self):
        _write(self.test_dir, ".secscanignore", "# fixtures\nfixtures/\n*.min.js\n")
        _write(self.test_dir, "fixtures/creds.py", 'password = "SuperSecretPassword123!"\n')
        _write(self.test_dir, "app.min.js", "el.innerHTML = data;\n")
        _write(self.test_dir, "real.py", 'password = "SuperSecretPassword123!"\n')
        results = SecScanOrchestrator(verbose=False).run(self.test_dir)
        self.assertEqual(results["context"]["ignored_files"], 2)
        self.assertEqual({os.path.basename(f["file"]) for f in results["findings"]}, {"real.py"})


# ════════════════════════════════════════════════════════════
# Reporte visual (HTML/PDF), i18n e insights
# ════════════════════════════════════════════════════════════

LEAK_CANARIES = ("P@ssw0rd2024!", "MyDatabaseP@ssw0rd!", "sk-live-4eC39HqLyjWDarjtT1zdp7dc",
                 "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "SuperSecret123!", "password123",
                 "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", "my-jwt-secret-key-very-weak")


def _weasyprint_available():
    try:
        import weasyprint  # noqa: F401
        return True
    except (ImportError, OSError):
        return False


class TestInsights(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from report.insights import build_insights
        cls.results = SecScanOrchestrator(verbose=False).run(TEST_PROJECT, os.path.join(TEST_PROJECT, "logs"))
        cls.ins = build_insights(cls.results)

    def test_threats_are_separated_from_exposure(self):
        self.assertEqual(self.ins["exposure_total"] + self.ins["threat_total"], self.results["total_findings"])
        self.assertTrue(all(e["tool"] != "LogAnalyzer" for e in self.ins["entries"] if not e["is_threat"]))
        self.assertGreater(self.ins["threat_events"], 0)

    def test_verdict_and_score(self):
        from report.insights import risk_score
        self.assertEqual(self.ins["verdict"], "critical")
        self.assertEqual(risk_score([]), 0)
        low = risk_score([{"severity": "BAJA", "confidence": "BAJA"}])
        high = risk_score([{"severity": "CRITICA", "confidence": "ALTA"}])
        self.assertLess(low, high)
        self.assertLessEqual(self.ins["risk_score"], 100)

    def test_actions_cover_every_finding(self):
        self.assertEqual(sum(a["count"] for a in self.ins["actions"]), self.results["total_findings"])
        keys = [a["key"] for a in self.ins["actions"]]
        self.assertIn("rotate_credentials", keys)
        self.assertIn("parametrize_sql", keys)

    def test_snippets_are_redacted(self):
        dumped = repr([e["snippet"] for e in self.ins["entries"]])
        for secret in LEAK_CANARIES:
            self.assertNotIn(secret, dumped)


class TestI18n(unittest.TestCase):
    def test_all_languages_have_all_keys(self):
        from report.i18n import STRINGS, DEFAULT_LANG
        base = set(STRINGS[DEFAULT_LANG])
        for lang, strings in STRINGS.items():
            self.assertEqual(base - set(strings), set(), f"faltan claves en {lang}")

    def test_english_html(self):
        from report.html_report import render_html
        results = SecScanOrchestrator(verbose=False).run(TEST_PROJECT)
        html_text = render_html(results, lang="en")
        self.assertIn('lang="en"', html_text)
        self.assertIn("Executive summary", html_text)
        self.assertNotIn("Resumen ejecutivo", html_text)


class TestHtmlReport(TempDirTestCase):
    def test_self_contained_and_secret_free(self):
        from report.html_report import render_html
        results = SecScanOrchestrator(verbose=False).run(TEST_PROJECT, os.path.join(TEST_PROJECT, "logs"))
        html_text = render_html(results)
        self.assertNotRegex(html_text, r'(?:src|href)="https?://')  # funciona sin internet
        self.assertIn("@font-face", html_text)
        for secret in LEAK_CANARIES:
            self.assertNotIn(secret, html_text)

    def test_css_string_cannot_break_out_of_style(self):
        from report.html_report import css_string
        self.assertNotRegex(str(css_string('x"; } </style><script>alert(1)</script>')), r'[<>"{};]')


@unittest.skipUnless(_weasyprint_available(), "WeasyPrint no disponible")
class TestPdfReport(TempDirTestCase):
    def test_pdf_generation(self):
        from pypdf import PdfReader
        from report.generator import ReportGenerator
        results = SecScanOrchestrator(verbose=False).run(TEST_PROJECT, os.path.join(TEST_PROJECT, "logs"))
        for lang, heading in (("es", "Resumen ejecutivo"), ("en", "Executive summary")):
            path = ReportGenerator().generate(results, format="pdf", output_dir=os.path.join(self.test_dir, lang), lang=lang)
            reader = PdfReader(path)
            self.assertGreater(len(reader.pages), 3)
            text = "\n".join(page.extract_text() for page in reader.pages)
            self.assertIn(heading, text)
            for secret in LEAK_CANARIES:
                self.assertNotIn(secret, text)


class TestNoEmojis(unittest.TestCase):
    """La interfaz usa íconos SVG y etiquetas de texto, no emojis."""

    EMOJI = __import__("re").compile("[\U0001F300-\U0001FAFF\u2600-\u26FF\u2B00-\u2BFF\uFE0F]")

    def test_sources_have_no_emojis(self):
        offenders = []
        for root, dirs, files in os.walk(REPO_ROOT):
            dirs[:] = [d for d in dirs if d not in {".git", ".venv", "venv", "__pycache__", "reports", "assets"}]
            for name in files:
                if name.endswith((".py", ".md", ".j2", ".txt")):
                    path = os.path.join(root, name)
                    with open(path, encoding="utf-8", errors="ignore") as f:
                        if self.EMOJI.search(f.read()):
                            offenders.append(os.path.relpath(path, REPO_ROOT))
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()


class TestContextAwareDetection(unittest.TestCase):
    """Los detectores distinguen código real de texto (strings, docstrings, reportes)."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def write(self, name, content):
        path = os.path.join(self.test_dir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    def test_xss_ignores_text_but_detects_code(self):
        path = self.write("rules.py", (
            '"""Este módulo detecta eval() y render_template_string()."""\n'
            'RULE = {"name": "eval() con input", "desc": "document.write() es peligroso"}\n'
            '# render_template_string(x) en un comentario\n'
            'def view(x):\n'
            '    eval(x)\n'
            '    return render_template_string(x)\n'
            'PAGE = """\n<script>el.innerHTML = data;</script>\n"""\n'
        ))
        lines = sorted(f["line"] for f in detect_xss([path]))
        self.assertEqual(lines, [5, 6, 8])  # eval, render_template_string, innerHTML en HTML embebido

    def test_xss_invalid_python_falls_back_to_lines(self):
        path = self.write("broken.py", 'def (:\n    eval(user)\n')
        self.assertEqual([f["line"] for f in detect_xss([path])], [2])

    def test_config_ignores_docstrings(self):
        path = self.write("settings.py", (
            '"""Revisa DEBUG = True y CORS (Access-Control-Allow-Origin: *)."""\n'
            'DEBUG = True\n'
        ))
        self.assertEqual([f["line"] for f in audit_config([path])], [2])

    def test_planner_skips_generated_reports(self):
        os.makedirs(os.path.join(self.test_dir, "reports"))
        self.write("reports/x.html", '<meta name="generator" content="SecScan Agent">\nrender_template_string(')
        self.write("reports/security_report_20260101_120000.html", "<style>...</style>")
        self.write("app.py", "eval(x)\n")
        ctx = Planner().analyze_context(self.test_dir)
        self.assertEqual([os.path.basename(f) for f in ctx.file_list], ["app.py"])
        self.assertEqual(ctx.ignored_files, 2)

    def test_repository_scans_clean(self):
        """El propio repositorio no debe reportarse a sí mismo (lo usarían para evaluarlo)."""
        repo = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        results = SecScanOrchestrator(verbose=False).run(repo)
        self.assertEqual(results["total_findings"], 0, [(f["file"], f["line"], f["type"]) for f in results["findings"]])
