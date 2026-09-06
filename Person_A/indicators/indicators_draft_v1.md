# SPIDER Security Indicators — Draft v1

## Command Execution
- os.system()
- subprocess.run()
- subprocess.Popen()

## Dynamic Code Execution
- eval()
- exec()
- compile()
- exec(compile(...))

## Credential / Data Access
- os.environ access
- reading ~/.ssh/
- reading ~/.aws/credentials
- reading .netrc
- reading .env files
- credential/data access combined with network activity

## Network Activity
- socket usage
- HTTP requests
- remote content downloads

## Obfuscation
- base64 encoding/decoding
- encoded strings
- dynamically reconstructed strings

## Install-Time / Package Execution
- setup.py execution
- package initialization code
- installation hooks

## Supply-Chain Abuse
- typosquatting
- dependency confusion
- package impersonation