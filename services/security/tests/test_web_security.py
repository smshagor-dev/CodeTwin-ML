from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

SERVICE_ROOT = Path(__file__).resolve().parents[1]
if str(SERVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVICE_ROOT))

from codetwin_security.analyzer import scan_repository
from codetwin_security.cli import main


class WebSecurityAnalyzerTests(unittest.TestCase):
    def test_detects_python_web_and_database_risks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "from flask import request\n"
                "import requests\n"
                "cursor.execute(f\"SELECT * FROM users WHERE id={request.args['id']}\")\n"
                "requests.get(request.args['url'])\n"
                "app.run(debug=True)\n",
                encoding="utf-8",
            )
            result = scan_repository(root)
            rules = {finding.rule_id for finding in result.findings}
            self.assertIn("web.sql.dynamic_query", rules)
            self.assertIn("web.sql.request_to_query", rules)
            self.assertIn("web.ssrf.request_url", rules)
            self.assertIn("web.debug.enabled", rules)

    def test_detects_js_xss_command_cors_and_jwt_misconfiguration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "server.ts").write_text(
                "element.innerHTML = req.query.html;\n"
                "child_process.exec(req.query.command);\n"
                "const headers = {'Access-Control-Allow-Origin': '*'};\n"
                "const token = jwt.decode(raw, {verify_signature: False});\n",
                encoding="utf-8",
            )
            result = scan_repository(root)
            rules = {finding.rule_id for finding in result.findings}
            self.assertIn("web.xss.request_to_html", rules)
            self.assertIn("web.command.request_to_process", rules)
            self.assertIn("web.cors.wildcard", rules)
            self.assertIn("web.jwt.verification_disabled", rules)

    def test_detects_php_database_request_flow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "user.php").write_text(
                "$row = mysqli_query($db, \"SELECT * FROM users WHERE id=\" . $_GET['id']);\n",
                encoding="utf-8",
            )
            result = scan_repository(root)
            self.assertTrue(any(item.rule_id == "web.sql.request_to_query" for item in result.findings))

    def test_parameterized_query_is_not_reported_as_dynamic_sql(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "safe.py").write_text(
                "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))\n",
                encoding="utf-8",
            )
            result = scan_repository(root)
            self.assertFalse(any(item.rule_id.startswith("web.sql") for item in result.findings))

    def test_generated_directories_are_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generated = root / "node_modules" / "package"
            generated.mkdir(parents=True)
            (generated / "bad.js").write_text("element.innerHTML = req.query.html;\n", encoding="utf-8")
            result = scan_repository(root)
            self.assertEqual(result.files_considered, 0)
            self.assertEqual(result.findings, ())

    def test_secret_like_evidence_is_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "settings.py").write_text(
                "token = 'do-not-print-this'; DEBUG = True\n",
                encoding="utf-8",
            )
            result = scan_repository(root)
            debug = next(item for item in result.findings if item.rule_id == "web.debug.enabled")
            self.assertNotIn("do-not-print-this", debug.evidence)
            self.assertIn("<redacted>", debug.evidence)

    def test_cli_json_and_fail_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("app.run(debug=True)\n", encoding="utf-8")
            self.assertEqual(main([str(root), "--format", "json"]), 0)
            self.assertEqual(main([str(root), "--fail-on", "medium"]), 2)


if __name__ == "__main__":
    unittest.main()
