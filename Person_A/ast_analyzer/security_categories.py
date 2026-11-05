"""
SPIDER Security Categories and Default Severities.

Six active behavioral categories are emitted by the AST analyzer for v1:
1. Command Execution (HIGH)
2. Dynamic Code Execution (HIGH)
3. Credential / Data Access (HIGH)
4. Network Activity (MEDIUM)
5. Obfuscation (MEDIUM)
6. Install-Time / Package Execution (HIGH for custom install commands/cmdclass, LOW for standard setup)

Note on categories:
- "Supply-Chain Abuse" is reserved at the metadata/package-naming level (typosquatting, dependency confusion)
  and is not emitted as an AST rule finding.
- "Parse Error" is an analysis status (recorded in inventory.parse_failures and failed_static_analysis),
  not a security behavior category.
"""

ACTIVE_CATEGORIES = [
    "Command Execution",
    "Dynamic Code Execution",
    "Credential / Data Access",
    "Network Activity",
    "Obfuscation",
    "Install-Time / Package Execution",
]

RESERVED_CATEGORIES = [
    "Supply-Chain Abuse",
]

SECURITY_CATEGORIES = {
    "Command Execution": "HIGH",
    "Dynamic Code Execution": "HIGH",
    "Credential / Data Access": "HIGH",
    "Network Activity": "MEDIUM",
    "Obfuscation": "MEDIUM",
    "Install-Time / Package Execution": "HIGH",
    "Supply-Chain Abuse": "HIGH",  # Reserved metadata category
}
