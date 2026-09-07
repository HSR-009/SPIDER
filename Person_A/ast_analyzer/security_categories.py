# SECURITY_RULES = {
#     "Command Execution": [
#         "os.system",
#         "subprocess.run",
#         "subprocess.Popen",
#     ],

#     "Dynamic Code Execution": [
#         "eval",
#         "exec",
#         "compile",
#     ],

#     "Credential / Data Access": [
#         "os.environ",
#         "~/.ssh/",
#         "~/.aws/credentials",
#         ".netrc",
#         ".env",
#     ],

#     "Network Activity": [
#         "socket",
#         "requests",
#         "urllib",
#         "http",
#     ],

#     "Obfuscation": [
#         "base64",
#         "encoded_string",
#         "dynamic_reconstruction",
#     ],

#     "Install-Time / Package Execution": [
#         "setuptools.command.install",
#         "cmdclass",
#         "setup.py",
#         "__init__.py",
#     ],

#     "Supply-Chain Abuse": [
#         "typosquatting",
#         "dependency_confusion",
#         "package_impersonation",
#     ],
# }
SECURITY_CATEGORIES = {
    "Command Execution": "HIGH",
    "Dynamic Code Execution": "HIGH",
    "Credential / Data Access": "HIGH",
    "Network Activity": "MEDIUM",
    "Obfuscation": "MEDIUM",
    "Install-Time / Package Execution": "HIGH",
    "Supply-Chain Abuse": "HIGH",
}