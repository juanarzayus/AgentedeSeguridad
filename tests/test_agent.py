"""
Pruebas unitarias para SecScan Agent.
Verifica el funcionamiento de los Tools, el Planner y el Orchestrator.
"""

import unittest
import os
import shutil
import tempfile
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


if __name__ == "__main__":
    unittest.main()
