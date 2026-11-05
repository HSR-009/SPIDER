"""
SPIDER AST Security Analyzer (Person A Core Engine).
Provides static AST analysis of Python source files and directories:
- analyze_file: parses a single Python file, detects indicators across 6 security categories,
  and attaches exact source location metadata (lineno, col_offset, end_lineno, snippet, rule_id).
- scan_directory: recursively inventories and analyzes a package folder, inspecting setup/build hooks,
  recording uninspected native artifacts (.so, .dll, .pth), tracking coverage, and emitting
  honest 3-way verdicts (suspicious, none_detected_in_this_scan, unable_to_assess).
"""

import ast
import os
from pathlib import Path
from typing import Dict, List, Any, Optional

from Person_A.ast_analyzer.security_categories import SECURITY_CATEGORIES
from spider_contract.dataset import make_group_id

def evaluate_constant_str(node: ast.AST) -> Optional[str]:
    """
    Statically evaluates constant string expressions, including binary string concatenations (+).
    Deterministic and strictly static: never executes code.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = evaluate_constant_str(node.left)
        right = evaluate_constant_str(node.right)
        if left is not None and right is not None:
            return left + right
    return None

def _extract_snippet(lines: List[str], lineno: Optional[int], end_lineno: Optional[int]) -> str:
    """Safely extracts the source code line or span corresponding to a finding."""
    if lineno is None or not (1 <= lineno <= len(lines)):
        return ""
    # Single-line snippet
    return lines[lineno - 1].strip()

def analyze_file(file_path: str) -> List[Dict[str, Any]]:
    """
    Statically analyzes a single Python file using AST.
    Safely catches SyntaxError and I/O errors, returning structured finding dictionaries.
    """
    if not os.path.exists(file_path):
        return [{
            "category": "Parse Error",
            "indicator": "FileNotFound",
            "severity": "MEDIUM",
            "file": file_path,
            "line": 0,
            "col_offset": 0,
            "end_lineno": 0,
            "end_col_offset": 0,
            "snippet": "",
            "rule_id": "RULE_PARSE_FILE_NOT_FOUND",
            "evidence": f"File does not exist: {file_path}"
        }]

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
    except Exception as e:
        return [{
            "category": "Parse Error",
            "indicator": "IOError",
            "severity": "MEDIUM",
            "file": file_path,
            "line": 0,
            "col_offset": 0,
            "end_lineno": 0,
            "end_col_offset": 0,
            "snippet": "",
            "rule_id": "RULE_PARSE_IO_ERROR",
            "evidence": f"Unable to read file: {e}"
        }]

    lines = source.splitlines()

    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError as e:
        snippet = ""
        if e.lineno and 1 <= e.lineno <= len(lines):
            snippet = lines[e.lineno - 1].strip()
        return [{
            "category": "Parse Error",
            "indicator": "SyntaxError",
            "severity": "MEDIUM",
            "file": file_path,
            "line": e.lineno or 0,
            "col_offset": e.offset or 0,
            "end_lineno": e.end_lineno or e.lineno or 0,
            "end_col_offset": e.end_offset or e.offset or 0,
            "snippet": snippet,
            "rule_id": "RULE_PARSE_SYNTAX_ERROR",
            "evidence": f"Unable to parse Python source: {e.msg}"
        }]

    aliases: Dict[str, str] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    aliases[alias.name.split(".")[0]] = alias.name.split(".")[0]

        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                full_name = f"{node.module}.{alias.name}" if node.module else alias.name
                aliases[alias.asname or alias.name] = full_name

    findings: List[Dict[str, Any]] = []

    def make_finding(cat: str, ind: str, sev: str, rule_id: str, ev: str, node: ast.AST) -> Dict[str, Any]:
        lno = getattr(node, "lineno", None)
        col = getattr(node, "col_offset", None)
        elno = getattr(node, "end_lineno", lno)
        ecol = getattr(node, "end_col_offset", None)
        snp = _extract_snippet(lines, lno, elno)
        return {
            "category": cat,
            "indicator": ind,
            "severity": sev,
            "file": file_path,
            "line": lno,
            "col_offset": col,
            "end_lineno": elno,
            "end_col_offset": ecol,
            "snippet": snp,
            "rule_id": rule_id,
            "evidence": ev
        }

    for node in ast.walk(tree):

        # --- 1. Command Execution ---
        if isinstance(node, ast.Call):
            # os.system (direct or alias)
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and aliases.get(node.func.value.id) == "os"
                and node.func.attr == "system"
            ) or (
                isinstance(node.func, ast.Name)
                and aliases.get(node.func.id) == "os.system"
            ):
                findings.append(make_finding(
                    "Command Execution", "os.system",
                    SECURITY_CATEGORIES["Command Execution"],
                    "RULE_CMD_OS_SYSTEM", "os.system() call detected", node
                ))

            # subprocess.run
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and aliases.get(node.func.value.id) == "subprocess"
                and node.func.attr == "run"
            ) or (
                isinstance(node.func, ast.Name)
                and aliases.get(node.func.id) == "subprocess.run"
            ):
                findings.append(make_finding(
                    "Command Execution", "subprocess.run",
                    SECURITY_CATEGORIES["Command Execution"],
                    "RULE_CMD_SUBPROCESS_RUN", "subprocess.run() call detected", node
                ))

            # subprocess.Popen
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and aliases.get(node.func.value.id) == "subprocess"
                and node.func.attr == "Popen"
            ) or (
                isinstance(node.func, ast.Name)
                and aliases.get(node.func.id) == "subprocess.Popen"
            ):
                findings.append(make_finding(
                    "Command Execution", "subprocess.Popen",
                    SECURITY_CATEGORIES["Command Execution"],
                    "RULE_CMD_SUBPROCESS_POPEN", "subprocess.Popen() call detected", node
                ))

            # subprocess.call / subprocess.check_output
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and aliases.get(node.func.value.id) == "subprocess" and node.func.attr in ("call", "check_output"):
                attr = node.func.attr
                findings.append(make_finding(
                    "Command Execution", f"subprocess.{attr}",
                    SECURITY_CATEGORIES["Command Execution"],
                    f"RULE_CMD_SUBPROCESS_{attr.upper()}", f"subprocess.{attr}() call detected", node
                ))
            elif isinstance(node.func, ast.Name) and aliases.get(node.func.id) in ("subprocess.call", "subprocess.check_output"):
                target_ind = aliases[node.func.id]
                findings.append(make_finding(
                    "Command Execution", target_ind,
                    SECURITY_CATEGORIES["Command Execution"],
                    f"RULE_CMD_{target_ind.replace('.', '_').upper()}", f"{target_ind}() call detected", node
                ))

            # os.popen
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and aliases.get(node.func.value.id) == "os"
                and node.func.attr == "popen"
            ) or (
                isinstance(node.func, ast.Name)
                and aliases.get(node.func.id) == "os.popen"
            ):
                findings.append(make_finding(
                    "Command Execution", "os.popen",
                    SECURITY_CATEGORIES["Command Execution"],
                    "RULE_CMD_OS_POPEN", "os.popen() call detected", node
                ))

            # Dynamic invocation via getattr() e.g. getattr(os, "sys" + "tem")(...)
            if isinstance(node.func, ast.Call) and isinstance(node.func.func, ast.Name) and node.func.func.id == "getattr" and len(node.func.args) >= 2:
                target_module = getattr(node.func.args[0], "id", None)
                real_target = aliases.get(target_module, target_module)
                attr_name = evaluate_constant_str(node.func.args[1])

                if real_target == "os" and attr_name == "system":
                    findings.append(make_finding(
                        "Command Execution", "os.system",
                        SECURITY_CATEGORIES["Command Execution"],
                        "RULE_CMD_GETATTR_SYSTEM", "os.system call detected via getattr() dynamic dispatch", node
                    ))
                elif real_target == "subprocess" and attr_name in ("run", "Popen", "call", "check_output"):
                    findings.append(make_finding(
                        "Command Execution", f"subprocess.{attr_name}",
                        SECURITY_CATEGORIES["Command Execution"],
                        "RULE_CMD_GETATTR_SUBPROCESS", f"subprocess.{attr_name} call detected via getattr() dynamic dispatch", node
                    ))
                elif real_target in ("__builtins__", "builtins") and attr_name in ("exec", "eval", "compile"):
                    findings.append(make_finding(
                        "Dynamic Code Execution", attr_name,
                        SECURITY_CATEGORIES["Dynamic Code Execution"],
                        "RULE_DYN_GETATTR_EXEC", f"{attr_name}() call detected via getattr() dynamic dispatch", node
                    ))
                elif attr_name is None:
                    findings.append(make_finding(
                        "Dynamic Code Execution", "getattr.dynamic",
                        "LOW",
                        "RULE_DYN_GETATTR_NON_CONST", "getattr() invocation with non-constant attribute name", node
                    ))

            # Standalone getattr(os, "system") or getattr(subprocess, "run")
            if isinstance(node.func, ast.Name) and node.func.id == "getattr" and len(node.args) >= 2:
                target_module = getattr(node.args[0], "id", None)
                real_target = aliases.get(target_module, target_module)
                attr_name = evaluate_constant_str(node.args[1])
                if real_target == "os" and attr_name == "system":
                    findings.append(make_finding(
                        "Command Execution", "os.system",
                        SECURITY_CATEGORIES["Command Execution"],
                        "RULE_CMD_GETATTR_SYSTEM", "os.system resolved via getattr()", node
                    ))
                elif real_target == "subprocess" and attr_name in ("run", "Popen", "call", "check_output"):
                    findings.append(make_finding(
                        "Command Execution", f"subprocess.{attr_name}",
                        SECURITY_CATEGORIES["Command Execution"],
                        "RULE_CMD_GETATTR_SUBPROCESS", f"subprocess.{attr_name} resolved via getattr()", node
                    ))
                elif attr_name is None:
                    # Non-constant attribute name
                    findings.append(make_finding(
                        "Dynamic Code Execution", "getattr.dynamic",
                        "LOW",
                        "RULE_DYN_GETATTR_NON_CONST", "getattr() with non-constant attribute name", node
                    ))

        # --- 2. Dynamic Code Execution ---
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id == "eval":
                    findings.append(make_finding(
                        "Dynamic Code Execution", "eval",
                        SECURITY_CATEGORIES["Dynamic Code Execution"],
                        "RULE_DYN_EVAL", "eval() call detected", node
                    ))
                elif node.func.id == "exec":
                    findings.append(make_finding(
                        "Dynamic Code Execution", "exec",
                        SECURITY_CATEGORIES["Dynamic Code Execution"],
                        "RULE_DYN_EXEC", "exec() call detected", node
                    ))
                elif node.func.id == "compile":
                    findings.append(make_finding(
                        "Dynamic Code Execution", "compile",
                        SECURITY_CATEGORIES["Dynamic Code Execution"],
                        "RULE_DYN_COMPILE", "compile() call detected", node
                    ))

        # --- 3. Credential / Data Access ---
        if isinstance(node, ast.Attribute):
            if (
                isinstance(node.value, ast.Name)
                and aliases.get(node.value.id) == "os"
                and node.attr == "environ"
            ):
                findings.append(make_finding(
                    "Credential / Data Access", "os.environ",
                    SECURITY_CATEGORIES["Credential / Data Access"],
                    "RULE_CRED_OS_ENVIRON", "os.environ access detected", node
                ))

        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            sensitive_paths = [".ssh/", ".aws/credentials", ".netrc", ".env"]
            for path in sensitive_paths:
                if path in node.value:
                    findings.append(make_finding(
                        "Credential / Data Access", path,
                        SECURITY_CATEGORIES["Credential / Data Access"],
                        "RULE_CRED_SENSITIVE_PATH", f"Sensitive path {path} detected", node
                    ))

        # --- 4. Network Activity ---
        if isinstance(node, ast.Call):
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and aliases.get(node.func.value.id) == "socket"
                and node.func.attr == "socket"
            ):
                findings.append(make_finding(
                    "Network Activity", "socket",
                    SECURITY_CATEGORIES["Network Activity"],
                    "RULE_NET_SOCKET", "socket() call detected", node
                ))

            if isinstance(node.func, ast.Attribute):
                if (
                    isinstance(node.func.value, ast.Name)
                    and aliases.get(node.func.value.id) == "requests"
                    and node.func.attr in ["get", "post", "request"]
                ):
                    findings.append(make_finding(
                        "Network Activity", f"requests.{node.func.attr}",
                        SECURITY_CATEGORIES["Network Activity"],
                        f"RULE_NET_REQUESTS_{node.func.attr.upper()}", "Network request detected", node
                    ))
                elif (
                    node.func.attr == "urlopen"
                    and isinstance(node.func.value, ast.Attribute)
                    and isinstance(node.func.value.value, ast.Name)
                    and aliases.get(node.func.value.value.id) == "urllib"
                    and node.func.value.attr == "request"
                ):
                    findings.append(make_finding(
                        "Network Activity", "urllib.request.urlopen",
                        SECURITY_CATEGORIES["Network Activity"],
                        "RULE_NET_URLOPEN", "Network request detected", node
                    ))
            elif isinstance(node.func, ast.Name) and aliases.get(node.func.id) == "urllib.request.urlopen":
                findings.append(make_finding(
                    "Network Activity", "urllib.request.urlopen",
                    SECURITY_CATEGORIES["Network Activity"],
                    "RULE_NET_URLOPEN", "Network request detected", node
                ))

        # --- 5. Obfuscation ---
        if isinstance(node, ast.Call):
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and aliases.get(node.func.value.id) == "base64"
            ):
                findings.append(make_finding(
                    "Obfuscation", f"base64.{node.func.attr}",
                    SECURITY_CATEGORIES["Obfuscation"],
                    "RULE_OBF_BASE64", "base64 operation detected", node
                ))
            elif (
                isinstance(node.func, ast.Name)
                and aliases.get(node.func.id, "").startswith("base64.")
            ):
                ind = aliases[node.func.id]
                findings.append(make_finding(
                    "Obfuscation", ind,
                    SECURITY_CATEGORIES["Obfuscation"],
                    "RULE_OBF_BASE64_IMPORT", "Imported base64 operation detected", node
                ))

        # --- 6. Install-Time / Package Execution ---
        if isinstance(node, ast.Call):
            if (
                isinstance(node.func, ast.Name)
                and (node.func.id == "setup" or aliases.get(node.func.id) == "setuptools.setup")
            ):
                # Context-aware severity: check if custom cmdclass is passed to setup()
                has_custom_cmdclass = any(kw.arg == "cmdclass" for kw in node.keywords)
                if has_custom_cmdclass:
                    findings.append(make_finding(
                        "Install-Time / Package Execution", "setuptools.setup.cmdclass",
                        "HIGH", "RULE_INST_SETUP_CMDCLASS",
                        "setuptools.setup() with custom cmdclass install hook detected", node
                    ))
                else:
                    # Fix severity bias: plain standard setup() is informational (LOW), not HIGH
                    findings.append(make_finding(
                        "Install-Time / Package Execution", "setuptools.setup",
                        "LOW", "RULE_INST_SETUP_STANDARD",
                        "Standard setuptools.setup() call detected (informational)", node
                    ))

        if isinstance(node, ast.ImportFrom):
            if node.module == "setuptools.command.install":
                findings.append(make_finding(
                    "Install-Time / Package Execution", "setuptools.command.install",
                    "HIGH", "RULE_INST_CUSTOM_CMD",
                    "Custom setuptools install command detected", node
                ))

    return findings

def scan_directory(dir_path: str, max_file_size: int = 2 * 1024 * 1024) -> Dict[str, Any]:
    """
    Recursively scans a package directory, inventories files and uninspected native artifacts,
    inspects build hooks (setup.py, pyproject.toml, setup.cfg), runs AST analysis on Python code,
    and derives a calibrated 3-way verdict (suspicious, none_detected_in_this_scan, unable_to_assess).
    """
    path_obj = Path(dir_path).resolve()

    record: Dict[str, Any] = {
        "schema_version": "0.1.0",
        "package_name": path_obj.name,
        "version": "",
        "package_id": path_obj.name,
        "group_id": make_group_id(path_obj.name),
        "analyzer_version": "v1.0.0",
        "verdict": "unable_to_assess",
        "review_recommended": False,
        "findings": [],
        "category_counts": {
            "Command Execution": 0,
            "Dynamic Code Execution": 0,
            "Credential / Data Access": 0,
            "Network Activity": 0,
            "Obfuscation": 0,
            "Install-Time / Package Execution": 0,
        },
        "n_findings": 0,
        "n_py_files": 0,
        "parse_error_count": 0,
        "failed_static_analysis": 0,
        "record_origin": "scan",
        "inventory": {
            "inspected_files": [],
            "parse_failures": [],
            "uninspected_files": [],
            "vendored_paths": [],
            "limits_hit": [],
        }
    }

    if not path_obj.exists() or not path_obj.is_dir():
        record["inventory"]["limits_hit"].append(f"Directory not found or inaccessible: {dir_path}")
        return record

    all_py_files: List[Path] = []
    vendored_names = {"_vendor", "vendor", "third_party", "bundled", "site-packages", "node_modules"}
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "env", ".tox", ".pytest_cache"}
    unsupported_exts = {".so", ".dll", ".dylib", ".pyd", ".exe", ".bin", ".pyc", ".pyo"}

    # Walk directory
    for root, dirs, files in os.walk(path_obj):
        # Prune internal and environment directories
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        rel_root = os.path.relpath(root, path_obj)
        is_vendored = any(part.lower() in vendored_names for part in Path(rel_root).parts)

        for f in files:
            file_path = Path(root) / f
            rel_file_path = os.path.relpath(file_path, path_obj)
            ext = file_path.suffix.lower()

            if is_vendored:
                record["inventory"]["vendored_paths"].append(rel_file_path)

            if ext in (".py", ".pyw"):
                all_py_files.append(file_path)
            elif ext in unsupported_exts:
                # Explicit v1 policy: non-Python compiled artifacts are inventoried as uninspected
                record["inventory"]["uninspected_files"].append({
                    "path": rel_file_path,
                    "type": ext,
                    "reason": "unsupported_compiled_binary"
                })
            elif ext == ".pth":
                # Startup persistence hook check
                try:
                    pth_content = file_path.read_text(encoding="utf-8", errors="ignore")
                    lines = [ln.strip() for ln in pth_content.splitlines() if ln.strip()]
                    has_code = any(ln.startswith(("import ", "exec(")) for ln in lines)
                    if has_code:
                        record["findings"].append({
                            "category": "Install-Time / Package Execution",
                            "indicator": "startup_hook.pth",
                            "severity": "HIGH",
                            "file": rel_file_path,
                            "line": 1,
                            "col_offset": 0,
                            "end_lineno": 1,
                            "end_col_offset": 0,
                            "snippet": lines[0] if lines else "",
                            "rule_id": "RULE_INST_PTH_STARTUP",
                            "evidence": "Startup hook execution detected in .pth file"
                        })
                    record["inventory"]["inspected_files"].append(rel_file_path)
                except Exception as e:
                    record["inventory"]["limits_hit"].append(f"Failed to read .pth: {e}")

    # Inspect pyproject.toml build hooks if present
    pyproject_path = path_obj / "pyproject.toml"
    if pyproject_path.exists():
        try:
            content = pyproject_path.read_text(encoding="utf-8", errors="ignore")
            # Look for non-standard build backend
            if "build-backend" in content:
                for line in content.splitlines():
                    if "build-backend" in line and not any(std in line for std in ["setuptools.build_meta", "flit_core.buildapi", "hatchling.build", "poetry.core.masonry.api"]):
                        record["findings"].append({
                            "category": "Install-Time / Package Execution",
                            "indicator": "custom_build_backend",
                            "severity": "MEDIUM",
                            "file": "pyproject.toml",
                            "line": 1,
                            "col_offset": 0,
                            "end_lineno": 1,
                            "end_col_offset": 0,
                            "snippet": line.strip(),
                            "rule_id": "RULE_INST_CUSTOM_BUILD_BACKEND",
                            "evidence": f"Custom pyproject.toml build backend detected: {line.strip()}"
                        })
        except Exception as e:
            record["inventory"]["limits_hit"].append(f"pyproject.toml read error: {e}")

    # Inspect setup.cfg if present
    setup_cfg_path = path_obj / "setup.cfg"
    if setup_cfg_path.exists():
        try:
            cfg_text = setup_cfg_path.read_text(encoding="utf-8", errors="ignore")
            if "[cmdclass]" in cfg_text:
                record["findings"].append({
                    "category": "Install-Time / Package Execution",
                    "indicator": "setup_cfg_cmdclass",
                    "severity": "HIGH",
                    "file": "setup.cfg",
                    "line": 1,
                    "col_offset": 0,
                    "end_lineno": 1,
                    "end_col_offset": 0,
                    "snippet": "[cmdclass]",
                    "rule_id": "RULE_INST_SETUP_CFG_CMDCLASS",
                    "evidence": "setup.cfg overrides installation cmdclass"
                })
        except Exception as e:
            record["inventory"]["limits_hit"].append(f"setup.cfg read error: {e}")

    # Run AST analysis on Python files
    record["n_py_files"] = len(all_py_files)

    for py_file in all_py_files:
        rel_py = os.path.relpath(py_file, path_obj)
        try:
            sz = py_file.stat().st_size
            if sz > max_file_size:
                record["inventory"]["limits_hit"].append(f"File exceeds max size limit ({sz} > {max_file_size}): {rel_py}")
                continue
        except OSError:
            pass

        file_findings = analyze_file(str(py_file))

        # Check for parse failure
        parse_err = next((f for f in file_findings if f["category"] == "Parse Error"), None)
        if parse_err:
            record["parse_error_count"] += 1
            record["failed_static_analysis"] = 1
            record["inventory"]["parse_failures"].append({
                "file": rel_py,
                "error": parse_err["evidence"]
            })
        else:
            record["inventory"]["inspected_files"].append(rel_py)

        # Normalize relative path in findings
        for f in file_findings:
            if f["category"] != "Parse Error":
                f["file"] = rel_py
                record["findings"].append(f)
                cat = f["category"]
                if cat in record["category_counts"]:
                    record["category_counts"][cat] += 1

    record["n_findings"] = len(record["findings"])

    # --- Derive 3-way Honest Verdict ---
    inspected_count = len(record["inventory"]["inspected_files"])
    uninspected_count = len(record["inventory"]["uninspected_files"])
    total_found_files = inspected_count + record["parse_error_count"] + uninspected_count

    # 1. Unable to assess if: no files found, or only native binaries found, or >20% parse failures
    if total_found_files == 0:
        record["verdict"] = "unable_to_assess"
    elif inspected_count == 0 and uninspected_count > 0:
        record["verdict"] = "unable_to_assess"
    elif record["parse_error_count"] > 0 and (record["parse_error_count"] / max(1, inspected_count + record["parse_error_count"])) > 0.20:
        record["verdict"] = "unable_to_assess"
    else:
        # Combination-based Verdict v2 (Sprint Plan):
        # suspicious requires a strong combination or dedicated install hook:
        # 1. Custom install hook or startup .pth
        # 2. Dynamic code execution (exec/eval) combined with obfuscation or network
        # 3. Base64 decode combined with exec/eval
        # 4. Credential access combined with network exfiltration
        # 5. Dynamic invocation via getattr concealing execution
        indicators = set(f["indicator"] for f in record["findings"])
        categories = set(f["category"] for f in record["findings"])

        has_custom_install = any(
            f["indicator"] in ("setuptools.command.install", "setuptools.setup.cmdclass", "setup_cfg_cmdclass", "startup_hook.pth")
            for f in record["findings"]
        )
        has_dyn_exec = any(
            f["category"] == "Dynamic Code Execution" and f.get("indicator") != "getattr.dynamic"
            for f in record["findings"]
        )
        has_obf = ("Obfuscation" in categories)
        has_net = ("Network Activity" in categories)

        has_b64_decode = any(
            "decode" in f["indicator"] for f in record["findings"] if f["category"] == "Obfuscation"
        )
        has_b64_with_exec = has_b64_decode and has_dyn_exec

        has_cred_path = any(
            f["indicator"] in (".ssh/", ".aws/credentials", ".netrc", ".env") for f in record["findings"]
        )
        has_cred_with_net = (has_cred_path and has_net) or ("os.environ" in indicators and "requests.post" in indicators)

        has_dyn_with_obf_or_net = has_dyn_exec and (has_obf or has_net)
        has_getattr_evasion = any(
            f.get("rule_id") in ("RULE_CMD_GETATTR_SYSTEM", "RULE_CMD_GETATTR_SUBPROCESS", "RULE_DYN_GETATTR_EXEC")
            and f.get("indicator") != "getattr.dynamic"
            for f in record["findings"]
        )

        strong_suspicious = (
            has_custom_install
            or has_b64_with_exec
            or has_dyn_with_obf_or_net
            or has_cred_with_net
            or has_getattr_evasion
        )

        if strong_suspicious:
            record["verdict"] = "suspicious"
        else:
            record["verdict"] = "none_detected_in_this_scan"
            if record["n_findings"] > 0:
                record["review_recommended"] = True

    return record
