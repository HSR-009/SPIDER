# Analyzer v1.1 Rule Specification

Specification of all AST rules implemented in `Person_A/ast_analyzer/analyzer_v1_1.py`.

## Rule Table

| rule_id | indicator | category | severity | confidence | AST shape / Trigger pattern |
|---|---|---|---|---|---|
| `cmd.os_system` | `os.system` | `Command Execution` | `HIGH` | `high` | Call to `os.system` (direct or via import alias) |
| `cmd.os_popen` | `os.popen` | `Command Execution` | `HIGH` | `high` | Call to `os.popen` (direct or via import alias) |
| `cmd.subprocess_run` | `subprocess.run` | `Command Execution` | `HIGH` | `high` | Call to `subprocess.run` (direct or via import alias) |
| `cmd.subprocess_popen` | `subprocess.Popen` | `Command Execution` | `HIGH` | `high` | Call to `subprocess.Popen` (direct or via import alias) |
| `cmd.subprocess_call` | `subprocess.call` | `Command Execution` | `HIGH` | `high` | Call to `subprocess.call` (direct or via import alias) |
| `cmd.subprocess_check_call` | `subprocess.check_call` | `Command Execution` | `HIGH` | `high` | Call to `subprocess.check_call` (direct or via import alias) |
| `cmd.subprocess_check_output` | `subprocess.check_output` | `Command Execution` | `HIGH` | `high` | Call to `subprocess.check_output` (direct or via import alias) |
| `<rule>.getattr` | `<indicator>` | `<category>` | `<severity>` | `high` | `getattr(module, "target")` where `target` is a constant string matching any known rule in `CALL_RULES` |
| `dyn.getattr_nonconst` | `getattr.dynamic` | `Dynamic Code Execution` | `LOW` | `medium` | `getattr(target, non_constant_expr)` where attribute name is dynamically computed |
| `dyn.eval` | `eval` | `Dynamic Code Execution` | `HIGH` | `high` | Call to builtin `eval` (unless shadowed by local function/class definition) |
| `dyn.exec` | `exec` | `Dynamic Code Execution` | `HIGH` | `high` | Call to builtin `exec` (unless shadowed by local function/class definition) |
| `dyn.compile` | `compile` | `Dynamic Code Execution` | `HIGH` | `high` | Call to builtin `compile` (unless shadowed by local function/class definition) |
| `dyn.dynamic_import` | `__import__(dynamic)` / `importlib.import_module(dynamic)` | `Dynamic Code Execution` | `MEDIUM` | `medium` | Call to `__import__` or `importlib.import_module` with a non-constant argument |
| `net.socket` | `socket` | `Network Activity` | `MEDIUM` | `high` | Call to `socket.socket` |
| `net.requests_get` | `requests.get` | `Network Activity` | `MEDIUM` | `high` | Call to `requests.get` |
| `net.requests_post` | `requests.post` | `Network Activity` | `MEDIUM` | `high` | Call to `requests.post` |
| `net.requests_request` | `requests.request` | `Network Activity` | `MEDIUM` | `high` | Call to `requests.request` |
| `net.urlopen` | `urllib.request.urlopen` | `Network Activity` | `MEDIUM` | `high` | Call to `urllib.request.urlopen` (direct or via import alias) |
| `obf.base64` | `base64.<method>` | `Obfuscation` | `MEDIUM` | `high` | Call to any method on `base64` module |
| `obf.fromhex` | `bytes.fromhex` | `Obfuscation` | `MEDIUM` | `medium` | Call to `bytes.fromhex` |
| `obf.chr_join` | `join(chr)` | `Obfuscation` | `MEDIUM` | `medium` | `''.join(chr(...) for ...)` generator/list comprehension |
| `cred.environ` | `os.environ` | `Credential / Data Access` | `HIGH` | `high` | Access to `os.environ` attribute or name in load context |
| `cred.path` | `.ssh/` | `Credential / Data Access` | `HIGH` | `medium` | String literal matching regex `\.ssh[/\\]` |
| `cred.path` | `.aws/credentials` | `Credential / Data Access` | `HIGH` | `medium` | String literal matching regex `\.aws[/\\]credentials` |
| `cred.path` | `.netrc` | `Credential / Data Access` | `HIGH` | `medium` | String literal matching regex `(^|[/\\])\.netrc($|[\s'"])` |
| `cred.path` | `.env` | `Credential / Data Access` | `HIGH` | `medium` | String literal matching regex `(^|[/\\])\.env($|\.[A-Za-z0-9_-]+$|[/\\\s'"])` |
| `inst.plain_setup` | `setuptools.setup` | `Install-Time / Package Execution` | `LOW` | `high` | Call to `setuptools.setup` or `distutils.core.setup` without `cmdclass` keyword (informational) |
| `inst.cmdclass` | `setuptools.setup.cmdclass` | `Install-Time / Package Execution` | `MEDIUM` | `medium` | Call to `setup()` containing keyword argument `cmdclass=...` |
| `inst.cmdclass` | `setup_cfg_cmdclass` | `Install-Time / Package Execution` | `MEDIUM` | `medium` | `setup.cfg` containing `[cmdclass]` section override |
| `inst.install_import` | `setuptools.command.install` | `Install-Time / Package Execution` | `HIGH` | `high` | Import from `setuptools.command.install` |
| `inst.install_override` | `install_command_override` | `Install-Time / Package Execution` | `HIGH` | `high` | Class definition subclassing setuptools/distutils install command and defining `run()` |

## Not Detected (Known Gaps)

The following attack vectors are intentionally outside the scope of AST analyzer v1.1:
- Dynamic string building to a call target other than via `getattr` (e.g., dynamically mutating `globals()` or `locals()`).
- Payload deserialization attacks via `pickle.loads()`, `marshal.loads()`, or `shelve`.
- Native payloads loaded via `ctypes` (`ctypes.CDLL`, `ctypes.windll`) or `cffi`.
- Non-Python payloads embedded inside data files (e.g., encrypted blobs decrypted and mapped into memory).
- Startup persistence hooks such as `.pth` files installed into site-packages (handled separately by the Hunter component).
- Obfuscated function target resolution via dictionary lookups on module dictionaries or `__builtins__.__dict__`.

## Intentional Differences from Frozen v1

1. **Precise `.env` Path Matching**: In frozen v1, `.env` was a simple substring match that produced false positives on legitimate strings like `os.environ` or `.envelope`. In v1.1, the pattern is anchored and requires a true path separator or extension boundary.
2. **Builtin Shadowing Guard**: If `eval`, `exec`, or `compile` is defined as a local function or class (`def eval(...)`), calls to it are recognized as local calls and are not flagged as dynamic code execution.
3. **Import Alias Resolution**: Resolves imports uniformly (`from os import system as sys_call`, `import subprocess as sp`), detecting calls that bypassed v1's direct name checks.
4. **Informational Plain Setup**: Standard `setup()` calls without custom overrides are rated `LOW` severity rather than `HIGH`, eliminating false-positive alerts on standard packaging files.
5. **Parse Failure Segregation**: Syntax errors and I/O failures are returned as `parse_failure` objects for inventory accounting, never as security findings.

