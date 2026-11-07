"""Trigger-phase rules for findings (section 7.4)."""
from typing import Any, Dict, List


def trigger_phase(finding: Dict[str, Any], roles: List[str]) -> str:
    """Determine trigger_phase -> install | import | call | unknown.
    
    1. Finding from rule inst.* -> install
    2. File role install_hook (root setup.py) and scope in (module, class) -> install; in function -> call
    3. File role startup_hook -> import
    4. Other files: scope module or class -> import; scope function -> call; in_main_guard true -> call
    5. Anything else -> unknown
    """
    rule_id = str(finding.get("rule_id", ""))
    if rule_id.startswith("inst."):
        return "install"

    scope = finding.get("scope", "module")
    in_main_guard = finding.get("in_main_guard", False)

    if "install_hook" in roles:
        if scope in ("module", "class"):
            return "install"
        elif scope == "function":
            return "call"

    if "startup_hook" in roles:
        return "import"

    if in_main_guard:
        return "call"

    if scope in ("module", "class"):
        return "import"
    elif scope == "function":
        return "call"

    return "unknown"
