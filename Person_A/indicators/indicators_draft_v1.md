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

## Day 3 — First-Pass Analyzer Observations

The AST analyzer was tested against the initial toy samples.

### Detected Malicious Indicators

The analyzer successfully detected:

- `os.system()`
- `subprocess.run()`
- `subprocess.Popen()`
- `eval()`
- `exec()`
- `compile()`
- `base64.b64decode`
- `socket`
- `setuptools.setup`
- `setuptools.command.install`

### Initial False-Positive Observations

Some indicators also appeared in legitimate clean samples:

- `subprocess.run()` may be used legitimately.
- `base64.b64encode()` may be used legitimately.

Therefore, the presence of a security-sensitive API alone does not establish
that a package is malicious.

These indicators should be treated as security signals that can later be
combined with other code and metadata features by the ML pipeline.

### Initial Analyzer Coverage

The current analyzer provides first-pass static indicators for:

- Command Execution
- Dynamic Code Execution
- Credential / Data Access
- Network Activity
- Obfuscation
- Install-Time / Package Execution

Supply-Chain Abuse remains primarily a package-name and metadata-level
indicator and is not directly represented by the current file-level AST
analysis.

## Day 3 — Indicator Analysis Conclusions

The first-pass analysis shows that Dynamic Code Execution and Command
Execution are the most frequently observed security categories in the toy
malicious samples, with 5 and 4 findings respectively.

Install-Time / Package Execution, Obfuscation, and Network Activity were also
observed, but less frequently in the current toy corpus.

The clean samples demonstrate that some security-sensitive APIs can occur in
legitimate software. In particular, `subprocess.run()` was observed in both
malicious and clean samples, while Base64 encoding was observed in clean code
and Base64 decoding was observed in malicious code. These indicators should
therefore not be treated as proof of malicious behavior by themselves.

Therefore, the indicators should be treated as individual signals rather
than independent proof of maliciousness.