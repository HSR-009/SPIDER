import os
import tempfile
import unittest
from Person_A.ast_analyzer.analyzer import analyze_file
from Person_A.ast_analyzer.security_categories import SECURITY_CATEGORIES

class TestAnalyzer(unittest.TestCase):
    def test_clean_sample_no_findings(self):
        sample = "data/toy_samples/clean/calculator.py"
        if os.path.exists(sample):
            findings = analyze_file(sample)
            self.assertEqual(len(findings), 0)

    def test_dynamic_code_execution_compile(self):
        sample = "data/toy_samples/malicious/compile.py"
        if os.path.exists(sample):
            findings = analyze_file(sample)
            self.assertGreaterEqual(len(findings), 1)
            categories = [f["category"] for f in findings]
            self.assertIn("Dynamic Code Execution", categories)
            indicators = [f["indicator"] for f in findings]
            self.assertIn("compile", indicators)

    def test_obfuscation_encoded_exec(self):
        sample = "data/toy_samples/malicious/encoded_exec.py"
        if os.path.exists(sample):
            findings = analyze_file(sample)
            self.assertGreaterEqual(len(findings), 2)
            categories = [f["category"] for f in findings]
            self.assertIn("Obfuscation", categories)
            self.assertIn("Dynamic Code Execution", categories)

    def test_command_execution_system(self):
        sample = "data/toy_samples/malicious/system_command.py"
        if os.path.exists(sample):
            findings = analyze_file(sample)
            self.assertGreaterEqual(len(findings), 1)
            categories = [f["category"] for f in findings]
            self.assertIn("Command Execution", categories)
            self.assertEqual(findings[0]["severity"], "HIGH")

    def test_parse_error_handling(self):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write("def broken_syntax(:\n    pass\n")
            temp_path = f.name

        try:
            findings = analyze_file(temp_path)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["category"], "Parse Error")
            self.assertEqual(findings[0]["indicator"], "SyntaxError")
            self.assertEqual(findings[0]["severity"], "MEDIUM")
            self.assertIn("Unable to parse Python source", findings[0]["evidence"])
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_import_alias_resolution(self):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write("import os as my_os\nmy_os.system('id')\n")
            temp_path = f.name

        try:
            findings = analyze_file(temp_path)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["category"], "Command Execution")
            self.assertEqual(findings[0]["indicator"], "os.system")
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_finding_fields_conformance(self):
        sample = "data/toy_samples/malicious/compile.py"
        if os.path.exists(sample):
            findings = analyze_file(sample)
            for f in findings:
                self.assertIn("category", f)
                self.assertIn("indicator", f)
                self.assertIn("severity", f)
                self.assertIn("file", f)
                self.assertIn("line", f)
                self.assertIn("evidence", f)
                self.assertIn(f["severity"], ["HIGH", "MEDIUM"])

if __name__ == "__main__":
    unittest.main()
