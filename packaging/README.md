# Offline release inputs

`swarma-keymaker.service` is byte-for-byte the ordered ini block in
[specification section 12.1](../spec/keymaker.md#121-explicit-preflight-and-dynamic-service-ids).
The release tool checks the unit and specification from the requested commit.
`TestReleaseUnitMatchesSpec` compares the shipped files and rejects additions,
removals, reordering and changed settings. Packaging adds no unit settings.

`config.example.json` uses the actual daemon Config decoder, also exposed as
`keymaker.ParseConfig` for offline use. Every member below is required; unknown,
missing, null and incorrectly typed members refuse. Duplicate members and trailing
JSON refuse. Parsing does not inspect installation paths or establish ownership,
account membership, state recovery or service readiness.

| Member | Type | Meaning |
| --- | --- | --- |
| socket_dir | absolute path string | Daemon-owned Unix socket directory. |
| state_dir | absolute path string | Dedicated custody state directory, separate from the master seed's immediate parent. |
| master_file | absolute path string | Protected 32-byte master seed; it is never a bundle input or output. |
| registry_file | absolute path string | Installed name-index registry location. |
| service_uid | uint32 | Numeric service-account pin; example 0 is a placeholder replaced by the section 12.1 allocator. |
| service_gid | uint32 | Numeric primary-group pin; example 0 is a placeholder replaced by the allocator. |
| control_gid | uint32 | Numeric registration-group pin; example 0 is a placeholder replaced by the allocator. Controls the exactly 0660 native socket group. |
| operator_principal | object with uint32 uid and string generation | Complete operator UID/generation authority tuple; replace both placeholders. |
| master_epoch | nonempty string | Operator-pinned master epoch; replace the example text. |
| registry_revision | nonempty string | Operator-pinned registry revision; replace the example text. |

Use an operator-supplied configuration, not an unchanged example. The allocator
in section 12.1 owns the numeric IDs; the offline parser accepts zero placeholders
so the runbook can replace them. The remaining file protection and identity
checks still run in the daemon.

## Bundle contract

Build and invoke `tools/release-bundle` using the root README's exact commands.
Required arguments are `-repo`, `-commit` (full HEAD SHA), `-version`, `-target`,
`-config` and `-name-indices`. The source must be a clean Git root at that commit,
including no staged, modified or untracked non-ignored files. The source constant
and the newly built binary's `version` output must both equal `-version`.

The target must not exist; its parent must exist, be under operator control and
have no symlink components. Targets inside source or under system roots such as
`/etc`, `/usr`, `/var` or `/run` refuse before target access. Use an offline scratch
location; protected staging remains the owner's section 12.1 responsibility.
Do not rename or modify inputs, source or the target's parent while building.
The tool is a local preparation tool using trusted Go and Git executables.

Operator input files must be regular, non-symlinked files, with no symlinked
ancestors and at most 8 MiB each. The configuration uses ParseConfig; the name
registry uses the daemon's StrictJSON and Registry.Validate. Validated bytes are
copied verbatim. No seed, private key, live state or credentials are copied.

| Target entry | Contents |
| --- | --- |
| keymaker | Linux binary for the builder's architecture, compiled with `-trimpath`, CGO disabled and no embedded local VCS paths. |
| config.json | Validated operator configuration. |
| name-indices.json | Validated operator name-index registry. |
| swarma-keymaker.service | Exact committed section 12.1 unit. |
| VERSION.json | Full source commit, actual CLI version, Go version, target OS/architecture and trimpath setting. |
| SHA256SUMS | Sorted SHA256 entries for all five files above. |

The source snapshot comes from `git archive` of the immutable commit; only
regular files and directories are extracted. Build HOME, temporary files,
module/cache directories and telemetry configuration are confined to the new
target's `.build` directory. The tool disables network module resolution,
workspace/global Go configuration and Git optional index writes. The binary's
embedded build settings are checked. Source cleanliness and HEAD are rechecked
before success. Build scratch is removed before manifest creation; failure
cleans only the newly created target whose directory identity still matches.
A pre-existing target and operator inputs are never removed or rewritten.

The final directory is private (0700), with binary 0700 and release data 0600;
the owner's runbook assigns installation ownership and modes. Exit 0 means the
offline files were assembled, 1 is refusal/build failure, and 2 is CLI misuse.
Child process PIDs are written to stderr. The tool neither invokes sudo/systemctl
nor creates accounts, installs files or starts a daemon. It writes only below
its newly created target.

## Explicit dependency gates

This branch targets the standard-library-only baseline. PR #5's enrollment
validator is not available here. With no `-enrollment`, enrollment.json is
omitted. Any supplied enrollment path refuses without opening it, with exactly
`enrollment validation unavailable at this revision`; it is never accepted by a
syntax-only JSON check. A follow-up after PR #5 must integrate its signed
snapshot/pins validator and review offline dependency availability before adding
that file. This revision cannot execute the runbook's unconditional enrollment
copy or qualify production enrollment.

`control_gid` and `operator_principal` use the landed native-control schema.
Socket mode is fixed at 0660 in the daemon, not a configurable member. Enrollment
pins use a separate configuration selected by the enrollment command's `--config`;
the serve configuration has no enrollment path member.

The generation adapter and signed operator verifier remain activation gates.
Section 12.1 also needs owner reconciliation with the dedicated `state_dir`
required by the current custody loader: the example uses a child state directory,
while the runbook currently creates only its parent. These are documented
handoff dependencies, not an alternate privileged procedure. Verification and
all root operations remain with the owner and the specification runbook.

## Test bounds

Tests use private temporary fixtures and clean clones of existing signed source
commits. They create no fixture commits, use no host signing key/SSH agent and
touch no system installation paths. A real positive build runs offline and checks
its manifest with `sha256sum -c`, then confirms a bounded corruption makes that
actual command exit 1 naming the changed file; refusal tests preserve inputs and existing
targets. Narrow commands and the two overlay controls are in the root README.
No formal attack-surface table was supplied in this brief. These packaging checks
do not qualify deployment, multi-UID behavior or the unavailable dependencies.

The existing mutation runner's optional packaging group plants two bounded
weakenings; the default ten core controls are unchanged. A plant is killed only
by exit 1 and its named test plus intended behavioral witness, not a build/setup
error. Both baseline negatives have valid clean/unit controls.

| Mutant | Narrows the gate to | Named failing test |
| --- | --- | --- |
| packaging-dirty-tree | Rejecting tracked modifications before bundle creation | TestReleaseDirtyTree/tracked |
| packaging-unit-drift | Exact unit equality, including a changed UMask | TestReleaseUnitMatchesSpec/modified |

These witnesses do not claim exhaustive mutation coverage. Surviving or unapplied
plants make the runner fail; they cannot be reported as killed.
