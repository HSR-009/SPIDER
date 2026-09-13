# SPIDER AST Analyzer v1 — Final

## Purpose

The AST analyzer performs first-pass static analysis of Python source code
to identify security-relevant indicators associated with potentially
malicious package behavior.

## Analysis Method

The analyzer uses Python AST parsing and rule-based matching.

It does not execute the analyzed source code.

## Detected Security Categories

- Command Execution
- Dynamic Code Execution
- Credential / Data Access
- Network Activity
- Obfuscation
- Install-Time / Package Execution
- Supply-Chain Abuse

## Detected Indicators

### Command Execution

- os.system()
- subprocess.run()
- subprocess.Popen()

### Dynamic Code Execution

- eval()
- exec()
- compile()

### Credential / Data Access

- os.environ
- ~/.ssh/
- ~/.aws/credentials
- .netrc
- .env

### Network Activity

- socket usage
- requests HTTP methods
- urllib.request.urlopen()

### Obfuscation

- base64 encoding/decoding

### Install-Time / Package Execution

- setuptools.setup()
- setuptools.command.install

## Output Format

Each finding contains:

- category
- indicator
- severity
- file
- line
- evidence

## Error Handling

Invalid Python syntax produces a `Parse Error` finding rather than
terminating the analysis.

Parse errors are not treated as security-category findings during
indicator analysis.

## Known Limitations

The analyzer performs direct AST-based rule matching.

It does not currently resolve dynamic indirection such as:

- getattr()-based function resolution
- dynamically constructed calls
- bytecode behavior
- runtime execution behavior

The analyzer also does not perform:

- sandbox execution
- symbolic execution
- bytecode analysis

## Day 3 Validation

The analyzer was tested against the initial toy corpus.

Malicious samples produced indicators from:

- Dynamic Code Execution
- Command Execution
- Install-Time / Package Execution
- Obfuscation
- Network Activity

Clean samples demonstrated that some security-sensitive APIs can also
appear in legitimate code.

Therefore, individual indicators are treated as security signals rather
than proof of maliciousness.

## Day 4 Adversarial Validation

The analyzer was tested against defined disguise techniques.

Two successful evasions were confirmed:

- system_command + getattr
- subprocess_call + getattr

Confirmed Attack Success Rate:

2 / 13 = 15.38%

The result demonstrates that direct AST matching can miss behavior hidden
through dynamic indirection.


## Final Status

AST Analyzer v1 is considered stable for integration with the ML feature
pipeline.

Future robustness improvements belong to the defense/re-testing phase and
should not change this baseline without documentation.
