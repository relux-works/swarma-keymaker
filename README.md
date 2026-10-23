# swarma-keymaker

Role: per-station key custody. Lore name: Keymaker.

Keymaker holds an installation's key material and performs narrowly permitted
operations for Unix peers identified by the kernel and an active account
generation. Private identity keys never enter station processes.

**Status: specification only.** There is no service binary, installer or deployed
security boundary in this repository. The vector tool is offline test tooling.
The proposed Linux v0 and publication gates are in
[`spec/keymaker.md`](spec/keymaker.md).

| Path | Contents |
| --- | --- |
| `spec/keymaker.md` | Normative candidate contract, operator runbook and test plan |
| `vectors/` | Paired refusal cases, published derivation controls and path examples |
| `tools/vectors/` | Reproducible Go derivation generator and fixture checks |
| `UNRESOLVED_QUESTIONS.md` | Index of decisions and activation gates |

## Tools

Run commands from the repository root. The tool uses only the Go standard
library (Go 1.26); no network or service credentials are needed.

| Tool | Purpose and exact command | Outputs |
| --- | --- | --- |
| Go | Check published SLIP-0010 controls, regenerate in memory and compare: `go run ./tools/vectors/main.go -check` | Summary on stdout; refuses mismatched fixtures |
| Go | Regenerate Keymaker derivation examples: `go run ./tools/vectors/main.go -write` | `vectors/keymaker-paths.json` |
| Python 3 | Check all JSON: `python3 -c 'import json,pathlib; [json.loads(p.read_text()) for p in pathlib.Path("vectors").glob("*.json")]'` | Exit status; no files |
| Git | Inspect scope: `git diff --check`; verify signed commits: `git log --format="%h %G?"` | Diagnostics on stdout |

The checks validate fixtures and derivation tooling. They do not qualify a
daemon, enforce kernel peer authentication or replace the pending integration
tests listed in the specification.
