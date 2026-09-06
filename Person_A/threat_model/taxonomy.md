# SPIDER Security Taxonomy

## 1. Command Execution

Code that executes operating-system commands.

Examples:
- os.system()
- subprocess.run()
- subprocess.Popen()

## 2. Dynamic Code Execution

Functions or patterns that execute dynamically supplied code.

Examples:
- eval()
- exec()
- compile()
- exec(compile(...))

## 3. Credential / Data Access

Code that accesses credentials, secrets, tokens, or sensitive local data.

Examples:
- os.environ access
- ~/.ssh/
- ~/.aws/credentials
- .netrc
- .env files

## 4. Network Activity

Code that communicates with external systems.

Examples:
- socket connections
- HTTP requests
- remote content downloads

## 5. Obfuscation

Techniques that may hide or transform potentially malicious code or strings.

Examples:
- base64 encoding/decoding
- encoded strings
- dynamically reconstructed strings

## 6. Install-Time / Package Execution

Code that executes during package installation or package initialization.

Examples:
- setup.py execution
- package initialization code
- installation hooks

## 7. Supply-Chain Abuse

Techniques that abuse the package ecosystem to distribute malicious code.

Examples:
- typosquatting
- dependency confusion
- malicious package impersonation

### 8. Toy Sample Exception

Supply-Chain Abuse does not have a toy Python sample because indicators
such as typosquatting and dependency confusion are primarily
name/metadata-based and cannot be meaningfully represented through
single-file AST analysis.