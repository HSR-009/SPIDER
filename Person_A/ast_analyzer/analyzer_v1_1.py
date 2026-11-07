"""SPIDER analyzer v1.1 (reference implementation).

Frozen v1 (Person_A/ast_analyzer/analyzer.py) is NOT edited. This module sits beside it.
Differences from v1 (all documented in Person_A/analysis/v1_1_rule_spec.md):
  * every finding carries line, col, end_line, end_col, snippet, rule_id, enclosing_function,
    scope ("module" | "class" | "function"), in_main_guard and confidence ("high" | "medium")
  * imports are resolved uniformly, so `from os import system`, `import subprocess as sp`,
    `from urllib.request import urlopen` and similar aliases are all understood
  * plain setup() is informational (severity LOW), not HIGH
  * new indicators: subprocess.call/check_call/check_output, os.popen, dynamic __import__ and
    importlib.import_module, bytes.fromhex(...).decode(), "".join(chr(...)), setup(cmdclass=...),
    install-command override (a subclass of the install command that defines run())
  * ".env" only matches a real path component, not ".environ" or ".envelope"
  * a parse failure is returned separately, never as a finding

v1 indicator names are kept wherever the behavior is the same, so v1 and v1.1 stay comparable.
"""
import ast
import re
import warnings

ANALYZER_VERSION = "analyzer-v1.1"
RULESET_VERSION = "rules-v1.1"

CMD, DYN, CRED, NET, OBF, INST = (
    "Command Execution",
    "Dynamic Code Execution",
    "Credential / Data Access",
    "Network Activity",
    "Obfuscation",
    "Install-Time / Package Execution",
)

# dotted callable name -> (category, indicator, severity, rule_id)
CALL_RULES = {
    "os.system": (CMD, "os.system", "HIGH", "cmd.os_system"),
    "os.popen": (CMD, "os.popen", "HIGH", "cmd.os_popen"),
    "subprocess.run": (CMD, "subprocess.run", "HIGH", "cmd.subprocess_run"),
    "subprocess.Popen": (CMD, "subprocess.Popen", "HIGH", "cmd.subprocess_popen"),
    "subprocess.call": (CMD, "subprocess.call", "HIGH", "cmd.subprocess_call"),
    "subprocess.check_call": (CMD, "subprocess.check_call", "HIGH", "cmd.subprocess_check_call"),
    "subprocess.check_output": (CMD, "subprocess.check_output", "HIGH", "cmd.subprocess_check_output"),
    "eval": (DYN, "eval", "HIGH", "dyn.eval"),
    "exec": (DYN, "exec", "HIGH", "dyn.exec"),
    "compile": (DYN, "compile", "HIGH", "dyn.compile"),
    "socket.socket": (NET, "socket", "MEDIUM", "net.socket"),
    "requests.get": (NET, "requests.get", "MEDIUM", "net.requests_get"),
    "requests.post": (NET, "requests.post", "MEDIUM", "net.requests_post"),
    "requests.request": (NET, "requests.request", "MEDIUM", "net.requests_request"),
    "urllib.request.urlopen": (NET, "urllib.request.urlopen", "MEDIUM", "net.urlopen"),
    "setuptools.setup": (INST, "setuptools.setup", "LOW", "inst.plain_setup"),
    "distutils.core.setup": (INST, "setuptools.setup", "LOW", "inst.plain_setup"),
}
BUILTINS_UNSHADOWED = {"eval", "exec", "compile", "setup"}
INSTALL_BASES = {"setuptools.command.install.install", "distutils.command.install.install"}
CRED_PATHS = [
    (".ssh/", re.compile(r"\.ssh[/\\]")),
    (".aws/credentials", re.compile(r"\.aws[/\\]credentials")),
    (".netrc", re.compile(r"(^|[/\\])\.netrc($|[\s'\"])")),
    (".env", re.compile(r"(^|[/\\])\.env($|\.[A-Za-z0-9_-]+$|[/\\\s'\"])")),
]


def _dotted(node, imports):
    """Resolve Name/Attribute chains through the import map: sp.run -> subprocess.run."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    root = imports.get(node.id, node.id)
    return ".".join([root] + list(reversed(parts)))


def _imports(tree):
    imports = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.asname:
                    imports[a.asname] = a.name
                else:
                    top = a.name.split(".")[0]
                    imports[top] = top
        elif isinstance(n, ast.ImportFrom) and n.module and not n.level:
            for a in n.names:
                imports[a.asname or a.name] = n.module + "." + a.name
    return imports


def _segment(source_lines, node):
    if node.end_lineno is None:
        return ""
    if node.lineno == node.end_lineno:
        text = source_lines[node.lineno - 1][node.col_offset:node.end_col_offset]
    else:
        text = source_lines[node.lineno - 1][node.col_offset:]
    return text.strip()[:200]


def _scopes(tree):
    """id(node) -> (enclosing_name, scope, in_main_guard).

    scope is "function", "class" or "module" (nearest enclosing def/class).
    in_main_guard is True inside `if __name__ == "__main__":`.
    """
    info = {}

    def is_main_guard(node):
        t = node.test
        return (isinstance(t, ast.Compare) and isinstance(t.left, ast.Name) and t.left.id == "__name__"
                and len(t.comparators) == 1 and isinstance(t.comparators[0], ast.Constant)
                and t.comparators[0].value == "__main__")

    def visit(node, name, scope, guard):
        for child in ast.iter_child_nodes(node):
            n, sc, g = name, scope, guard
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                n, sc = child.name, "function"
            elif isinstance(child, ast.ClassDef):
                n, sc = child.name, "class"
            elif isinstance(child, ast.If) and is_main_guard(child):
                # only the body is guarded, but marking the whole If is a safe approximation
                g = True
            info[id(child)] = (n, sc, g)
            visit(child, n, sc, g)

    visit(tree, None, "module", False)
    return info


# rules whose match is a heuristic rather than an exact API call
MEDIUM_CONFIDENCE = {"dyn.dynamic_import", "obf.fromhex", "obf.chr_join", "inst.cmdclass", "cred.path", "dyn.getattr_nonconst"}


def analyze_source(source, path):
    """Return (findings, parse_failure). parse_failure is None or {"path", "error", "line"}."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # invalid escape sequences etc. are not our concern
            tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError) as e:
        return [], {"path": path, "error": getattr(e, "msg", str(e)), "line": getattr(e, "lineno", None)}
    lines = source.splitlines() or [""]
    imports = _imports(tree)
    scopes = _scopes(tree)
    findings = []

    def add(node, cat, ind, sev, rule, why):
        findings.append({
            "rule_id": rule, "category": cat, "indicator": ind, "severity": sev, "file": path,
            "line": node.lineno, "col": node.col_offset,
            "end_line": getattr(node, "end_lineno", None), "end_col": getattr(node, "end_col_offset", None),
            "snippet": _segment(lines, node), "evidence": why,
            "enclosing_function": scopes.get(id(node), (None, "module", False))[0],
            "scope": scopes.get(id(node), (None, "module", False))[1],
            "in_main_guard": scopes.get(id(node), (None, "module", False))[2],
            "confidence": "medium" if rule in MEDIUM_CONFIDENCE else "high",
        })

    # A name counts as shadowed only if it is bound at MODULE level (module-level def, class, assignment, or import alias)
    shadowed = set()
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            shadowed.add(stmt.name)
        elif isinstance(stmt, ast.Assign):
            for t in stmt.targets:
                if isinstance(t, ast.Name):
                    shadowed.add(t.id)
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            shadowed.add(stmt.target.id)
    # Also include module-level import aliases
    shadowed.update(imports.keys())
    for n in ast.walk(tree):
        # Check for getattr(...) call (direct or invocation)
        if isinstance(n, ast.Call):
            # 1. getattr as the direct call: getattr(mod, "attr")
            # Or 2. invocation of getattr: getattr(mod, "attr")(args)
            getattr_node = None
            if isinstance(n.func, ast.Name) and n.func.id == "getattr" and "getattr" not in shadowed:
                getattr_node = n
            elif (isinstance(n.func, ast.Call) and isinstance(n.func.func, ast.Name)
                  and n.func.func.id == "getattr" and "getattr" not in shadowed):
                getattr_node = n.func

            if getattr_node and len(getattr_node.args) >= 2:
                target_mod = _dotted(getattr_node.args[0], imports)
                attr_arg = getattr_node.args[1]
                if isinstance(attr_arg, ast.Constant) and isinstance(attr_arg.value, str):
                    target_name = f"{target_mod}.{attr_arg.value}" if target_mod else attr_arg.value
                    if target_name in CALL_RULES:
                        cat, ind, sev, rule = CALL_RULES[target_name]
                        add(getattr_node, cat, ind, sev, f"{rule}.getattr", f"{ind}() call detected via getattr()")
                else:
                    ALLOWED_GETATTR_MODS = {"os", "subprocess", "sys", "importlib", "builtins", "socket", "requests", "base64"}
                    if target_mod in ALLOWED_GETATTR_MODS:
                        add(getattr_node, DYN, "getattr.dynamic", "LOW", "dyn.getattr_nonconst", "getattr with non-constant attribute name")

        if isinstance(n, ast.Call):
            name = _dotted(n.func, imports)
            if name in CALL_RULES and not (name in BUILTINS_UNSHADOWED and name in shadowed):
                cat, ind, sev, rule = CALL_RULES[name]
                add(n, cat, ind, sev, rule, "%s() call detected" % ind)
            elif isinstance(n.func, ast.Name) and n.func.id == "setup" and n.func.id not in imports:
                add(n, INST, "setuptools.setup", "LOW", "inst.plain_setup", "setup() call (informational)")
            if name and name.startswith("base64."):
                add(n, OBF, name, "MEDIUM", "obf.base64", "base64 operation detected")
            if name in ("__import__", "importlib.import_module") and n.args and not (
                isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str)
            ):
                add(n, DYN, name + "(dynamic)", "MEDIUM", "dyn.dynamic_import", "import with a non-constant name")
            if name == "bytes.fromhex":
                add(n, OBF, "bytes.fromhex", "MEDIUM", "obf.fromhex", "hex-decoded bytes")
            if (isinstance(n.func, ast.Attribute) and n.func.attr == "join" and n.args
                    and isinstance(n.args[0], (ast.GeneratorExp, ast.ListComp))
                    and isinstance(n.args[0].elt, ast.Call) and _dotted(n.args[0].elt.func, imports) == "chr"):
                add(n, OBF, "join(chr)", "MEDIUM", "obf.chr_join", "string built from chr() codes")
            if name == "setuptools.setup" or (isinstance(n.func, ast.Name) and n.func.id == "setup"):
                if any(k.arg == "cmdclass" for k in n.keywords):
                    add(n, INST, "setuptools.setup.cmdclass", "MEDIUM", "inst.cmdclass", "setup(cmdclass=...) overrides build commands")
        elif isinstance(n, ast.Attribute) or isinstance(n, ast.Name):
            name = _dotted(n, imports)
            if name == "os.environ" and not isinstance(getattr(n, "ctx", None), ast.Store):
                if isinstance(n, ast.Attribute) or imports.get(getattr(n, "id", ""), "") == "os.environ":
                    add(n, CRED, "os.environ", "HIGH", "cred.environ", "os.environ access detected")
        elif isinstance(n, ast.Constant) and isinstance(n.value, str):
            for ind, rx in CRED_PATHS:
                if rx.search(n.value):
                    add(n, CRED, ind, "HIGH", "cred.path", "Sensitive path %s detected" % ind)
        if isinstance(n, ast.ImportFrom) and n.module == "setuptools.command.install":
            add(n, INST, "setuptools.command.install", "HIGH", "inst.install_import", "Custom setuptools install command detected")
        if isinstance(n, ast.ClassDef):
            bases = {_dotted(b, imports) for b in n.bases}
            if bases & INSTALL_BASES and any(isinstance(m, ast.FunctionDef) and m.name == "run" for m in n.body):
                add(n, INST, "install_command_override", "HIGH", "inst.install_override", "install command overrides run()")
    # de-duplicate Name/Attribute double hits on the same os.environ node position
    seen, unique = set(), []
    for f in findings:
        key = (f["rule_id"], f["indicator"], f["line"], f["col"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique, None


def analyze_file(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return analyze_source(fh.read(), str(path))
