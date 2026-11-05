import ast

from Person_A.ast_analyzer.security_categories import SECURITY_CATEGORIES


def analyze_file(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        source = f.read()

    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError as e:
        return [{
            "category": "Parse Error",
            "indicator": "SyntaxError",
            "severity": "MEDIUM",
            "file": file_path,
            "line": e.lineno,
            "evidence": f"Unable to parse Python source: {e.msg}"
        }]

    aliases = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    aliases[alias.name.split(".")[0]] = alias.name.split(".")[0]

        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                full_name = f"{node.module}.{alias.name}"
                aliases[alias.asname or alias.name] = full_name

    findings = []

    for node in ast.walk(tree):

        # Command Execution - os.system
        if isinstance(node, ast.Call):
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and aliases.get(node.func.value.id) == "os"
                and node.func.attr == "system"
            ):
                findings.append({
                    "category": "Command Execution",
                    "indicator": "os.system",
                    "severity": SECURITY_CATEGORIES["Command Execution"],
                    "file": file_path,
                    "line": node.lineno,
                    "evidence": "os.system() call detected"
                })

        # Command Execution - subprocess.run
        if isinstance(node, ast.Call):
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and aliases.get(node.func.value.id) == "subprocess"
                and node.func.attr == "run"
            ):
                findings.append({
                    "category": "Command Execution",
                    "indicator": "subprocess.run",
                    "severity": SECURITY_CATEGORIES["Command Execution"],
                    "file": file_path,
                    "line": node.lineno,
                    "evidence": "subprocess.run() call detected"
                })

        # Command Execution - subprocess.Popen
        if isinstance(node, ast.Call):
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and aliases.get(node.func.value.id) == "subprocess"
                and node.func.attr == "Popen"
            ):
                findings.append({
                    "category": "Command Execution",
                    "indicator": "subprocess.Popen",
                    "severity": SECURITY_CATEGORIES["Command Execution"],
                    "file": file_path,
                    "line": node.lineno,
                    "evidence": "subprocess.Popen() call detected"
                })

        # Dynamic Code Execution - eval
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "eval":
                findings.append({
                    "category": "Dynamic Code Execution",
                    "indicator": "eval",
                    "severity": SECURITY_CATEGORIES["Dynamic Code Execution"],
                    "file": file_path,
                    "line": node.lineno,
                    "evidence": "eval() call detected"
                })

        # Dynamic Code Execution - exec
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "exec":
                findings.append({
                    "category": "Dynamic Code Execution",
                    "indicator": "exec",
                    "severity": SECURITY_CATEGORIES["Dynamic Code Execution"],
                    "file": file_path,
                    "line": node.lineno,
                    "evidence": "exec() call detected"
                })

        # Dynamic Code Execution - compile
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "compile":
                findings.append({
                    "category": "Dynamic Code Execution",
                    "indicator": "compile",
                    "severity": SECURITY_CATEGORIES["Dynamic Code Execution"],
                    "file": file_path,
                    "line": node.lineno,
                    "evidence": "compile() call detected"
                })

        # Credential / Data Access - os.environ
        if isinstance(node, ast.Attribute):
            if (
                isinstance(node.value, ast.Name)
                and aliases.get(node.value.id) == "os"
                and node.attr == "environ"
            ):
                findings.append({
                    "category": "Credential / Data Access",
                    "indicator": "os.environ",
                    "severity": SECURITY_CATEGORIES["Credential / Data Access"],
                    "file": file_path,
                    "line": node.lineno,
                    "evidence": "os.environ access detected"
                })

        # Credential / Data Access - sensitive paths
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            sensitive_paths = [
                ".ssh/",
                ".aws/credentials",
                ".netrc",
                ".env"
            ]

            for path in sensitive_paths:
                if path in node.value:
                    findings.append({
                        "category": "Credential / Data Access",
                        "indicator": path,
                        "severity": SECURITY_CATEGORIES["Credential / Data Access"],
                        "file": file_path,
                        "line": node.lineno,
                        "evidence": f"Sensitive path {path} detected"
                    })

        # Network Activity - socket
        if isinstance(node, ast.Call):
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and aliases.get(node.func.value.id) == "socket"
                and node.func.attr == "socket"
            ):
                findings.append({
                    "category": "Network Activity",
                    "indicator": "socket",
                    "severity": SECURITY_CATEGORIES["Network Activity"],
                    "file": file_path,
                    "line": node.lineno,
                    "evidence": "socket() call detected"
                })

        # Network Activity - requests / urllib
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):

                # requests.get/post/request
                if (
                    isinstance(node.func.value, ast.Name)
                    and aliases.get(node.func.value.id) == "requests"
                    and node.func.attr in ["get", "post", "request"]
                ):
                    findings.append({
                        "category": "Network Activity",
                        "indicator": f"requests.{node.func.attr}",
                        "severity": SECURITY_CATEGORIES["Network Activity"],
                        "file": file_path,
                        "line": node.lineno,
                        "evidence": "Network request detected"
                    })

                # urllib.request.urlopen
                elif (
                    node.func.attr == "urlopen"
                    and isinstance(node.func.value, ast.Attribute)
                    and isinstance(node.func.value.value, ast.Name)
                    and aliases.get(node.func.value.value.id) == "urllib"
                    and node.func.value.attr == "request"
                ):
                    findings.append({
                        "category": "Network Activity",
                        "indicator": "urllib.request.urlopen",
                        "severity": SECURITY_CATEGORIES["Network Activity"],
                        "file": file_path,
                        "line": node.lineno,
                        "evidence": "Network request detected"
                    })

        # Obfuscation - base64 module
        if isinstance(node, ast.Call):
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and aliases.get(node.func.value.id) == "base64"
            ):
                findings.append({
                    "category": "Obfuscation",
                    "indicator": f"base64.{node.func.attr}",
                    "severity": SECURITY_CATEGORIES["Obfuscation"],
                    "file": file_path,
                    "line": node.lineno,
                    "evidence": "base64 operation detected"
                })

        # Obfuscation - imported base64 function
        if isinstance(node, ast.Call):
            if (
                isinstance(node.func, ast.Name)
                and aliases.get(node.func.id, "").startswith("base64.")
            ):
                findings.append({
                    "category": "Obfuscation",
                    "indicator": aliases[node.func.id],
                    "severity": SECURITY_CATEGORIES["Obfuscation"],
                    "file": file_path,
                    "line": node.lineno,
                    "evidence": "Imported base64 operation detected"
                })

        # Install-Time / Package Execution - setup()
        if isinstance(node, ast.Call):
            if (
                isinstance(node.func, ast.Name)
                and (
                    node.func.id == "setup"
                    or aliases.get(node.func.id) == "setuptools.setup"
                )
            ):
                findings.append({
                    "category": "Install-Time / Package Execution",
                    "indicator": "setuptools.setup",
                    "severity": SECURITY_CATEGORIES["Install-Time / Package Execution"],
                    "file": file_path,
                    "line": node.lineno,
                    "evidence": "setuptools.setup() detected"
                })

        # Custom setuptools install command
        if isinstance(node, ast.ImportFrom):
            if node.module == "setuptools.command.install":
                findings.append({
                    "category": "Install-Time / Package Execution",
                    "indicator": "setuptools.command.install",
                    "severity": SECURITY_CATEGORIES["Install-Time / Package Execution"],
                    "file": file_path,
                    "line": node.lineno,
                    "evidence": "Custom setuptools install command detected"
                })

    return findings