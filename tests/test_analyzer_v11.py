import unittest

from Person_A.ast_analyzer.analyzer_v1_1 import analyze_source

def inds(src):
    f, err = analyze_source(src, "x.py")
    return {(x["category"], x["indicator"], x["severity"]) for x in f}, err

class V11(unittest.TestCase):
    def test_alias_forms_now_detected(self):
        self.assertIn(("Command Execution", "os.system", "HIGH"), inds("from os import system\nsystem('id')")[0])
        self.assertIn(("Command Execution", "subprocess.run", "HIGH"), inds("import subprocess as sp\nsp.run(['id'])")[0])
        self.assertIn(("Network Activity", "urllib.request.urlopen", "MEDIUM"), inds("from urllib.request import urlopen\nurlopen('http://x')")[0])
        self.assertIn(("Command Execution", "subprocess.check_output", "HIGH"), inds("import subprocess\nsubprocess.check_output(['id'])")[0])
        self.assertIn(("Command Execution", "os.popen", "HIGH"), inds("import os\nos.popen('id')")[0])
    def test_plain_setup_is_informational(self):
        got, _ = inds("from setuptools import setup\nsetup(name='a')")
        self.assertEqual(got, {("Install-Time / Package Execution", "setuptools.setup", "LOW")})
    def test_cmdclass_and_install_override(self):
        got, _ = inds("from setuptools import setup\nfrom setuptools.command.install import install\n"
                      "class X(install):\n    def run(self):\n        pass\nsetup(name='a', cmdclass={'install': X})")
        names = {i for _, i, _ in got}
        self.assertTrue({"setuptools.command.install", "install_command_override", "setuptools.setup.cmdclass"} <= names)
    def test_dynamic_import_only_when_non_constant(self):
        self.assertEqual(inds("__import__('os')")[0], set())
        self.assertIn(("Dynamic Code Execution", "__import__(dynamic)", "MEDIUM"), inds("n='o'+'s'\n__import__(n)")[0])
    def test_hex_and_chr_obfuscation(self):
        self.assertIn(("Obfuscation", "bytes.fromhex", "MEDIUM"), inds("bytes.fromhex('41')")[0])
        self.assertIn(("Obfuscation", "join(chr)", "MEDIUM"), inds("''.join(chr(c) for c in [65,66])")[0])
    def test_env_path_is_precise(self):
        self.assertEqual(inds("x = 'os.environment variable'")[0], set())
        self.assertIn(("Credential / Data Access", ".env", "HIGH"), inds("open('.env')")[0])
        self.assertIn(("Credential / Data Access", ".env", "HIGH"), inds("p = '/home/u/.env'")[0])
    def test_span_snippet_and_enclosing_function(self):
        f, _ = analyze_source("import os\n\ndef go():\n    os.system('id')\n", "x.py")
        self.assertEqual((f[0]["line"], f[0]["col"], f[0]["end_line"], f[0]["snippet"], f[0]["enclosing_function"]),
                         (4, 4, 4, "os.system('id')", "go"))
    def test_scope_and_main_guard(self):
        f, _ = analyze_source("import os\nos.system('a')\nclass C:\n    os.system('b')\n"
                              "def g():\n    os.system('c')\nif __name__ == '__main__':\n    os.system('d')\n", "x.py")
        by_line = {x["line"]: (x["scope"], x["in_main_guard"]) for x in f}
        self.assertEqual(by_line[2], ("module", False))
        self.assertEqual(by_line[4], ("class", False))
        self.assertEqual(by_line[6], ("function", False))
        self.assertEqual(by_line[8], ("module", True))
    def test_confidence(self):
        f, _ = analyze_source("import os\nos.system('a')\nn='x'\n__import__(n)\n", "x.py")
        conf = {x["indicator"]: x["confidence"] for x in f}
        self.assertEqual(conf["os.system"], "high")
        self.assertEqual(conf["__import__(dynamic)"], "medium")
    def test_parse_failure_is_not_a_finding(self):
        f, err = analyze_source("def (:\n", "bad.py")
        self.assertEqual(f, []); self.assertEqual(err["path"], "bad.py")
    def test_getattr_indirection_is_still_missed_until_normalization(self):
        # A non-constant attribute name is flagged as LOW getattr.dynamic
        self.assertEqual(
            inds("import os\ngetattr(os, 'sys'+'tem')('id')")[0],
            {("Dynamic Code Execution", "getattr.dynamic", "LOW")}
        )
    def test_shadowed_builtin_not_flagged(self):
        self.assertEqual(inds("def eval(x):\n    return x\neval(1)")[0], set())
    def test_shadowed_subprocess_not_flagged(self):
        self.assertEqual(inds("def run(cmd):\n    subprocess = 'local'\n    return len(cmd)\nrun('id')")[0], set())
    def test_constant_getattr_os(self):
        f, _ = analyze_source("import os\ngetattr(os, 'system')('id')\n", "x.py")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["indicator"], "os.system")
        self.assertEqual(f[0]["category"], "Command Execution")
        self.assertEqual(f[0]["severity"], "HIGH")
        self.assertEqual(f[0]["rule_id"], "cmd.os_system.getattr")
    def test_constant_getattr_subprocess(self):
        f, _ = analyze_source("import subprocess as sp\ngetattr(sp, 'run')(['id'])\n", "x.py")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["indicator"], "subprocess.run")
        self.assertEqual(f[0]["category"], "Command Execution")
        self.assertEqual(f[0]["severity"], "HIGH")
        self.assertEqual(f[0]["rule_id"], "cmd.subprocess_run.getattr")
    def test_non_constant_getattr(self):
        f, _ = analyze_source("import os\nname = 'sys' + 'tem'\ngetattr(os, name)\n", "x.py")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["indicator"], "getattr.dynamic")
        self.assertEqual(f[0]["category"], "Dynamic Code Execution")
        self.assertEqual(f[0]["severity"], "LOW")
        self.assertEqual(f[0]["rule_id"], "dyn.getattr_nonconst")
        self.assertEqual(f[0]["confidence"], "medium")
    def test_shadowed_getattr_not_flagged(self):
        src = "def getattr(obj, name):\n    return 42\ngetattr(None, 'system')\n"
        self.assertEqual(inds(src)[0], set())
    def test_non_constant_getattr_plus_requests_verdict(self):
        from spider_contract.adapter import convert_legacy_scan
        from spider_contract.verdict import derive_verdict
        src = "import os\nimport requests\nname = 'sys' + 'tem'\ngetattr(os, name)\nrequests.get('http://x')\n"
        f, _ = analyze_source(src, "x.py")
        rec = convert_legacy_scan(f, name="demo")
        rec["inventory"]["coverage_known"] = True
        v = derive_verdict(rec)
        self.assertEqual(v["outcome"], "none_detected_in_this_scan")
    def test_class_method_eval_does_not_shadow_builtin(self):
        src = "class H:\n    def eval(self): pass\nimport base64\neval(base64.b64decode(b'x'))\n"
        f, _ = analyze_source(src, "x.py")
        inds_found = {x["indicator"] for x in f}
        self.assertIn("eval", inds_found)
        self.assertTrue(any(i.startswith("base64.") for i in inds_found))
    def test_getattr_non_constant_allowed_modules(self):
        # getattr(os, name) -> flagged
        f1, _ = analyze_source("import os\nname = 'x'\ngetattr(os, name)\n", "x.py")
        self.assertIn("getattr.dynamic", [x["indicator"] for x in f1])
        # getattr(self, name) -> not flagged
        f2, _ = analyze_source("class Foo:\n    def m(self, name):\n        getattr(self, name)\n", "x.py")
        self.assertEqual(len(f2), 0)
    def test_getattr_subprocess_plus_requests_verdict(self):
        from spider_contract.adapter import convert_legacy_scan
        from spider_contract.verdict import derive_verdict
        src = "import subprocess\nimport requests\nname = 'run'\ngetattr(subprocess, name)\nrequests.get('http://x')\n"
        f, _ = analyze_source(src, "x.py")
        rec = convert_legacy_scan(f, name="demo")
        rec["inventory"]["coverage_known"] = True
        v = derive_verdict(rec)
        self.assertEqual(v["outcome"], "none_detected_in_this_scan")


class EquivalenceWithV1(unittest.TestCase):
    """v1.1 must never LOSE an indicator v1 finds (it may add new ones and lower plain setup())."""

    def test_toy_samples_are_a_superset_of_v1(self):
        import pathlib
        from Person_A.ast_analyzer.analyzer_v1_frozen import analyze_file as v1
        from Person_A.ast_analyzer.analyzer_v1_1 import analyze_file as v11
        root = pathlib.Path("data/toy_samples")
        if not root.exists():
            self.skipTest("run from the repository root")
        informational = {("Install-Time / Package Execution", "setuptools.setup")}
        for f in sorted(root.rglob("*.py")):
            old = {(x["category"], x["indicator"]) for x in v1(str(f)) if x["category"] != "Parse Error"}
            new = {(x["category"], x["indicator"]) for x in v11(str(f))[0]}
            self.assertFalse(old - new - informational, "%s lost %s" % (f, old - new))


if __name__ == "__main__":
    unittest.main()
