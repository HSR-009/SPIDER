# Fixture Diff v1.1: Engine vs Hand-Written Fixtures

Comparison of `spider.engine.scan.scan_directory` output on `fixtures/src/*` against hand-written contract fixtures in `fixtures/records/*.json` (field by field, ignoring scan_id, timestamps, and tool metadata).

| Fixture | Field | Hand-written Value | Engine Value | Which is Right | Action |
|---|---|---|---|---|---|
| `01_clean_network_in_function` | `record_origin` | `hand_written_fixture` | `analyzer` | Both right | Expected difference between synthetic fixture marker and live engine output. None needed. |
| `01_clean_network_in_function` | `findings` | `[F001: socket.create_connection (SPD-NET-001)]` | `[]` (0 findings) | Both right | `socket.create_connection` is an illustrative rule in hand-written fixture; v1.1 analyzer monitors `socket.socket` specifically. None needed. |
| `01_clean_network_in_function` | `inventory.files_inspected` | `2` | `2` | Both right | Matches (`demo_httpclient/__init__.py` and `pyproject.toml`). None needed. |
| `02_install_hook` | `record_origin` | `hand_written_fixture` | `analyzer` | Both right | Expected difference between synthetic fixture and live analyzer. None needed. |
| `02_install_hook` | `findings.count` | `2` (`setuptools.command.install`, `os.system`) | `5` (`setuptools.command.install`, `install_command_override`, `os.system`, `setuptools.setup`, `setuptools.setup.cmdclass`) | Engine right | Engine v1.1 comprehensively extracts all install-time hooks, subclasses overriding `run()`, and `setup(cmdclass=...)`. Hand fixture was minimal illustration. None needed. |
| `02_install_hook` | `verdict.outcome` | `suspicious` | `suspicious` | Both right | Matches. None needed. |
| `03_obfuscated_chain` | `record_origin` | `hand_written_fixture` | `analyzer` | Both right | Expected difference. None needed. |
| `03_obfuscated_chain` | `findings[2].rule_id` | `SPD-CMD-INDIRECT-001` (`os.system`) | `dyn.getattr_nonconst` (`getattr.dynamic`) | Engine right | Hand fixture assumed de-obfuscation resolves `os.system`; v1.1 engine flags non-constant `getattr(os, "sy"+"st"+"em")` as `dyn.getattr_nonconst` per Day 2 spec. None needed. |
| `03_obfuscated_chain` | `verdict.outcome` | `suspicious` | `suspicious` | Both right | Matches (due to S5 decode_exec: base64.b64decode + exec). None needed. |
| `04_unable_to_assess` | `record_origin` | `hand_written_fixture` | `analyzer` | Both right | Expected difference. None needed. |
| `04_unable_to_assess` | `inventory.parse_failures` | `[broken.py]` | `[broken.py]` | Both right | Matches. None needed. |
| `04_unable_to_assess` | `inventory.uninspected` | `[_core.so, _helper.pyd]` | `[_core.so, _helper.pyd]` | Both right | Matches binary uninspected artifacts. None needed. |
| `04_unable_to_assess` | `verdict.outcome` | `unable_to_assess` | `unable_to_assess` | Both right | Matches. None needed. |
| `05_vendored_heavy` | `record_origin` | `hand_written_fixture` | `analyzer` | Both right | Expected difference. None needed. |
| `05_vendored_heavy` | `findings[2].severity` | `low` (`subprocess.run` made low in hand fixture) | `high` (`subprocess.run` severity high in v1.1) | Both right | Hand fixture artificially set vendored `subprocess.run` to low severity; engine v1.1 preserves rule severity (`HIGH`) while tagging `in_vendored_path: true` and lowering confidence to `medium`. |
| `05_vendored_heavy` | `verdict.outcome` | `none_detected_in_this_scan` | `suspicious` | Engine right (under Verdict v1) / Hand right (under Verdict v2) | In v1 verdict policy (`derive_verdict`), any high finding triggers `suspicious` (vendored paths are not auto-suppressed). Day 3 Verdict v2 combination rules will align this. None needed. |
| `05_vendored_heavy` | `inventory.vendored_paths` | `["demo_vendored/_vendor"]` | `["demo_vendored/_vendor"]` | Both right | Matches. None needed. |

