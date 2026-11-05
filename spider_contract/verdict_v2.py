"""Verdict v2 reference: combination-based. Pure functions over a list of finding dicts.

A finding needs only: category, indicator, severity (any case). Works on v1, v1.1 and
scan_record findings alike.

strong_signals(findings) -> list of rule ids that fired
  S1 install_command   : indicator in {"setuptools.command.install", "install_command_override"}
  S2 dynamic_exec_plus : exec/eval/compile together with any Obfuscation OR any Network finding
  S3 credential_net    : a credential PATH (.ssh/, .aws/credentials, .netrc) together with Network
  S4 env_post          : os.environ together with requests.post
  S5 decode_exec       : a base64.* decode together with exec or eval

decide(findings, coverage_problems) -> (outcome, strong, review_recommended)
  suspicious      if strong is non-empty
  unable_to_assess if no strong signal and coverage_problems is non-empty
  none_detected_in_this_scan otherwise
  review_recommended = True when there is no strong signal but at least one HIGH finding
                       that is not the informational plain setup()
"""
# ".env" is deliberately NOT here: in the v1 data it is a substring match that also hits ".environ"-like
# strings (7.4% of benign packages). Add it back after the v1.1 rescan proves the tightened rule is precise.
CRED_PATHS = {".ssh/", ".aws/credentials", ".netrc"}
INSTALL = {"setuptools.command.install", "install_command_override"}


def strong_signals(findings):
    inds = {f["indicator"] for f in findings if f["category"] != "Parse Error"}
    cats = {f["category"] for f in findings if f["category"] != "Parse Error"}
    out = []
    if inds & INSTALL:
        out.append("S1_install_command")
    if inds & {"exec", "eval", "compile"} and ("Obfuscation" in cats or "Network Activity" in cats):
        out.append("S2_dynamic_exec_plus")
    if inds & CRED_PATHS and "Network Activity" in cats:
        out.append("S3_credential_net")
    if "os.environ" in inds and "requests.post" in inds:
        out.append("S4_env_post")
    if any(i.startswith("base64.") and i != "base64.b64encode" for i in inds) and inds & {"exec", "eval"}:
        out.append("S5_decode_exec")
    return out


def decide(findings, coverage_problems=()):
    strong = strong_signals(findings)
    if strong:
        return "suspicious", strong, False
    if coverage_problems:
        return "unable_to_assess", [], False
    review = any(
        str(f["severity"]).upper() == "HIGH" and f["indicator"] != "setuptools.setup"
        for f in findings if f["category"] != "Parse Error"
    )
    return "none_detected_in_this_scan", [], review
