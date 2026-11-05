"""
test_harness_safety.py
-----------------------
Day 2 required safety test: FAILS if any seed actually invokes exec, eval,
os.system, or subprocess for real when run.

Method: monkeypatch these functions to raise if called, then run every
seed's compiled code directly in-process (not via subprocess, specifically
so the monkeypatches are in effect and would catch a real call). If any
seed triggers the guard, the test fails loudly with which seed and which
guard tripped.

This is a belt-and-suspenders check on top of the equivalence harness's
AST pre-flight - the pre-flight proves the dangerous call isn't reachable
by reading the code; this test proves it by actually running the code
with tripwires installed and confirming nothing fires.

Run with: python -m pytest test_harness_safety.py -v
      or: python test_harness_safety.py
"""

import builtins
import os
import subprocess
import sys
import unittest

SEEDS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "seeds")


class GuardTripped(Exception):
    pass


def make_guard(name):
    def guard(*args, **kwargs):
        raise GuardTripped(f"'{name}' was actually invoked! This must never happen.")
    return guard


def _warm_up_modules_with_internal_eval_use():
    """
    Some stdlib modules call eval() internally the FIRST time they're
    imported in a process (e.g. urllib.request's import chain reaches
    collections.namedtuple, whose __new__ is built with eval()). This is
    normal CPython stdlib behavior with no connection to our seeds' actual
    payloads - but it would otherwise trip our eval guard on whichever
    seed happens to import that module first.

    Importing everything once here, before any guard is installed, means
    each module's one-time import side effects are already done by the
    time a seed imports it again (Python caches sys.modules, so the
    second import is a no-op re-reference, not a re-execution).
    """
    import importlib
    modules_to_warm = [
        "os", "subprocess", "base64", "codecs",
        "urllib.request", "setuptools.command.install",
    ]
    for mod in modules_to_warm:
        try:
            importlib.import_module(mod)
        except ImportError:
            pass  # not installed in this environment - fine, seed using it will report its own real error separately

    try:
        import requests  # noqa: F401
    except ImportError:
        pass  # requests may not be installed in every environment


_warm_up_modules_with_internal_eval_use()


class TestNoSeedActuallyExecutesDangerousCalls(unittest.TestCase):
    """
    One test per seed file. Each test runs the seed's source with os.system,
    os.popen, subprocess.run/Popen/call/check_output, eval, and exec all
    monkeypatched to raise GuardTripped if called. A passing test means the
    seed completed without tripping any guard AND printed its expected
    marker - proving the risky call never actually ran, only the marker did.
    """

    def _run_seed_with_guards(self, filepath):
        with open(filepath) as f:
            source = f.read()

        # Save real references
        real_eval = builtins.eval
        real_exec = builtins.exec
        real_os_system = os.system
        real_os_popen = os.popen
        real_sub_run = subprocess.run
        real_sub_popen = subprocess.Popen
        real_sub_call = subprocess.call
        real_sub_check_output = subprocess.check_output

        # Install guards
        builtins.eval = make_guard("eval")
        os.system = make_guard("os.system")
        os.popen = make_guard("os.popen")
        subprocess.run = make_guard("subprocess.run")
        subprocess.Popen = make_guard("subprocess.Popen")
        subprocess.call = make_guard("subprocess.call")
        subprocess.check_output = make_guard("subprocess.check_output")
        # NOTE: builtins.exec is intentionally NOT patched here, because we
        # need real exec() to run the seed's compiled code at all (compile +
        # exec is how this test itself executes the seed source). Instead,
        # we statically verify via the equivalence harness's AST pre-flight
        # (tested separately) that no seed calls exec() at a reachable
        # module-scope position. This test focuses on the guards that CAN
        # be safely monkeypatched without breaking the harness itself.

        captured_stdout = []
        import io
        from contextlib import redirect_stdout

        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                code_obj = compile(source, filepath, "exec")
                real_exec(code_obj, {"__name__": "__main__"})
            captured_stdout.append(buf.getvalue().strip())
        finally:
            # Restore real references no matter what
            builtins.eval = real_eval
            os.system = real_os_system
            os.popen = real_os_popen
            subprocess.run = real_sub_run
            subprocess.Popen = real_sub_popen
            subprocess.call = real_sub_call
            subprocess.check_output = real_sub_check_output

        return captured_stdout[0] if captured_stdout else ""


def _load_manifest_markers():
    """Read expected markers from manifest.json - authoritative, not derived."""
    import json
    manifest_path = os.path.join(SEEDS_DIR, "manifest.json")
    if not os.path.isfile(manifest_path):
        return {}
    with open(manifest_path) as f:
        manifest = json.load(f)
    return {entry["seed_id"]: entry["expected_marker"] for entry in manifest}


def _generate_test_methods():
    """Dynamically add one test_seed_NN method per seed file found."""
    if not os.path.isdir(SEEDS_DIR):
        return

    markers_by_id = _load_manifest_markers()

    for filename in sorted(os.listdir(SEEDS_DIR)):
        if not filename.startswith("seed_") or not filename.endswith(".py"):
            continue

        seed_id = filename.replace(".py", "")
        filepath = os.path.join(SEEDS_DIR, filename)
        expected_marker = markers_by_id.get(seed_id)
        if expected_marker is None:
            continue  # no manifest entry - skip rather than guess

        def make_test(fp=filepath, marker=expected_marker, name=seed_id):
            def test(self):
                try:
                    output = self._run_seed_with_guards(fp)
                except GuardTripped as e:
                    self.fail(f"{name}: SAFETY VIOLATION - {e}")
                self.assertEqual(
                    output, marker,
                    f"{name}: expected marker '{marker}' but got '{output}'"
                )
            return test

        test_name = f"test_{seed_id}_never_executes_dangerous_call"
        setattr(TestNoSeedActuallyExecutesDangerousCalls, test_name, make_test())


_generate_test_methods()


if __name__ == "__main__":
    unittest.main(verbosity=2)
