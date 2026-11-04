import os
import shutil
import tempfile
import unittest
from Person_A.ast_analyzer.analyzer import analyze_file, scan_directory
from Person_A.ast_analyzer.security_categories import SECURITY_CATEGORIES, ACTIVE_CATEGORIES

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

    def test_finding_source_locations_and_snippets(self):
        sample = "data/toy_samples/malicious/compile.py"
        if os.path.exists(sample):
            findings = analyze_file(sample)
            self.assertGreaterEqual(len(findings), 1)
            f = findings[0]
            self.assertIsNotNone(f["line"])
            self.assertIsNotNone(f["col_offset"])
            self.assertIsNotNone(f["end_lineno"])
            self.assertIsNotNone(f["snippet"])
            self.assertIsNotNone(f["rule_id"])
            self.assertTrue(len(f["snippet"]) > 0)
            self.assertTrue(f["rule_id"].startswith("RULE_"))

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
            self.assertEqual(findings[0]["rule_id"], "RULE_PARSE_SYNTAX_ERROR")
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_safe_handling_missing_file(self):
        findings = analyze_file("nonexistent_path_file_xyz_123.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["category"], "Parse Error")
        self.assertEqual(findings[0]["indicator"], "FileNotFound")

    def test_import_alias_resolution(self):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write("import os as my_os\nmy_os.system('id')\n")
            temp_path = f.name

        try:
            findings = analyze_file(temp_path)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["category"], "Command Execution")
            self.assertEqual(findings[0]["indicator"], "os.system")
            self.assertEqual(findings[0]["rule_id"], "RULE_CMD_OS_SYSTEM")
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_from_import_resolution(self):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write("from os import system\nsystem('whoami')\n")
            temp_path = f.name

        try:
            findings = analyze_file(temp_path)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["category"], "Command Execution")
            self.assertEqual(findings[0]["indicator"], "os.system")
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_getattr_dynamic_dispatch_direct(self):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write("import os\ngetattr(os, 'system')('whoami')\n")
            temp_path = f.name

        try:
            findings = analyze_file(temp_path)
            self.assertGreaterEqual(len(findings), 1)
            f_sys = next((f for f in findings if f["indicator"] == "os.system"), None)
            self.assertIsNotNone(f_sys)
            self.assertEqual(f_sys["category"], "Command Execution")
            self.assertEqual(f_sys["severity"], "HIGH")
            self.assertEqual(f_sys["rule_id"], "RULE_CMD_GETATTR_SYSTEM")
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_getattr_dynamic_dispatch_concatenated(self):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write("import os\ngetattr(os, 'sy' + 'st' + 'em')('whoami')\n")
            temp_path = f.name

        try:
            findings = analyze_file(temp_path)
            self.assertGreaterEqual(len(findings), 1)
            f_sys = next((f for f in findings if f["indicator"] == "os.system"), None)
            self.assertIsNotNone(f_sys)
            self.assertEqual(f_sys["category"], "Command Execution")
            self.assertEqual(f_sys["severity"], "HIGH")
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_getattr_subprocess_dispatch(self):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write("import subprocess\ngetattr(subprocess, 'run')(['id'])\n")
            temp_path = f.name

        try:
            findings = analyze_file(temp_path)
            self.assertGreaterEqual(len(findings), 1)
            f_sub = next((f for f in findings if f["indicator"] == "subprocess.run"), None)
            self.assertIsNotNone(f_sub)
            self.assertEqual(f_sub["category"], "Command Execution")
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_plain_setup_informational_severity(self):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write("from setuptools import setup\nsetup(name='sample', version='1.0')\n")
            temp_path = f.name

        try:
            findings = analyze_file(temp_path)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["category"], "Install-Time / Package Execution")
            self.assertEqual(findings[0]["indicator"], "setuptools.setup")
            # Must be LOW to avoid false positive high-severity alerts on benign packages
            self.assertEqual(findings[0]["severity"], "LOW")
            self.assertEqual(findings[0]["rule_id"], "RULE_INST_SETUP_STANDARD")
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_custom_cmdclass_setup_high_severity(self):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write("from setuptools import setup\nsetup(name='sample', cmdclass={'install': CustomInstall})\n")
            temp_path = f.name

        try:
            findings = analyze_file(temp_path)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["category"], "Install-Time / Package Execution")
            self.assertEqual(findings[0]["indicator"], "setuptools.setup.cmdclass")
            self.assertEqual(findings[0]["severity"], "HIGH")
            self.assertEqual(findings[0]["rule_id"], "RULE_INST_SETUP_CMDCLASS")
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_scan_directory_clean(self):
        clean_dir = "data/toy_samples/clean"
        if os.path.exists(clean_dir):
            record = scan_directory(clean_dir)
            self.assertEqual(record["verdict"], "none_detected_in_scan")
            self.assertGreater(record["n_py_files"], 0)
            self.assertEqual(record["parse_error_count"], 0)
            self.assertGreater(len(record["inventory"]["inspected_files"]), 0)

    def test_scan_directory_malicious(self):
        mal_dir = "data/toy_samples/malicious"
        if os.path.exists(mal_dir):
            record = scan_directory(mal_dir)
            self.assertEqual(record["verdict"], "suspicious")
            self.assertGreater(record["n_findings"], 0)
            self.assertIn("Command Execution", record["category_counts"])
            self.assertGreater(record["category_counts"]["Command Execution"], 0)

    def test_scan_directory_nonexistent_safe_fallback(self):
        record = scan_directory("completely_fake_dir_path_12345")
        self.assertEqual(record["verdict"], "unable_to_assess")
        self.assertGreater(len(record["inventory"]["limits_hit"]), 0)

    def test_scan_directory_uninspected_native_artifacts(self):
        temp_dir = tempfile.mkdtemp()
        try:
            # Create a mock native compiled extension and .pth file
            so_file = os.path.join(temp_dir, "native_payload.so")
            with open(so_file, "wb") as f:
                f.write(b"\x7fELF\x02\x01\x01\x00")

            pth_file = os.path.join(temp_dir, "startup.pth")
            with open(pth_file, "w", encoding="utf-8") as f:
                f.write("import os; os.system('id')\n")

            record = scan_directory(temp_dir)
            # Verify native artifact was recorded in uninspected_files
            uninspected_paths = [u["path"] for u in record["inventory"]["uninspected_files"]]
            self.assertIn("native_payload.so", uninspected_paths)
            # Verify pth file startup hook was detected
            pth_findings = [f for f in record["findings"] if f["indicator"] == "startup_hook.pth"]
            self.assertGreaterEqual(len(pth_findings), 1)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    unittest.main()
