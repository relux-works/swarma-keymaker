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
Inputs and source should remain stable for a successful build. Directory-handle
confinement remains enforced during parent/output substitutions.
The tool is a local preparation tool using trusted Go and Git executables.

Operator input files must be regular, non-symlinked files, with no symlinked
ancestors and at most 8 MiB each (enrollment pins are further limited to 1 MiB by their
parser). The configuration uses ParseConfig; the name
registry uses the daemon's StrictJSON and Registry.Validate. Optional enrollment
pins use enrollment.ParseConfig, sharing the landed strict schema and policy
checks; it does no Git, approval or retained-state operations. Validated bytes are
copied verbatim. No seed, private key, live state or credentials are copied.

| Target entry | Contents |
| --- | --- |
| keymaker | Linux binary for the builder's architecture, compiled with `-trimpath`, CGO disabled and no embedded local VCS paths. |
| config.json | Validated operator configuration. |
| name-indices.json | Validated operator name-index registry. |
| enrollment.json | Optional validated enrollment pin configuration, copied only when supplied. |
| swarma-keymaker.service | Exact committed section 12.1 unit. |
| VERSION.json | Full source commit, verified exported Git tree hash, actual CLI version, Go version, target OS/architecture and trimpath setting. |
| SHA256SUMS | Sorted SHA256 entries for all release files above, including enrollment.json when present. |

Every Git subprocess has a scrubbed environment, `--no-replace-objects` and
`GIT_NO_REPLACE_OBJECTS=1`. Grafts and shallow metadata are disabled, lazy fetching
and transports are disabled, and nonempty object alternates or symbolic object storage refuse. The raw
commit object is hash-checked against the requested ID. Its exact tree is
exported with `git archive`; regular-file bytes, executable modes and directory
entries are hashed independently using Git's object encoding before building.
A different export refuses before compilation. Links and other archive types
refuse. VERSION.json records the full commit and verified tree hash.

The target is created exclusively relative to a pinned parent. A parent writable
by other users refuses unless sticky and owned by the caller or root. The opened
root must be a directory owned by our euid, mode 0700 and empty. Final files and
manifest use `openat2` no-symlink resolution and exclusive creation. A ledger
records producer-created objects by device/inode from their creation handles,
and keeps those inodes and parent handles open until cleanup. Cleanup checks
identity, uses only nonrecursive unlink/rmdir, and preserves unknown entries,
substitutions and nonempty directories. The target itself remains after failure.

Every Git child and external Go build inherits a Landlock write boundary and
pinned scratch descriptor. Linux `openat2` and Landlock ABI >=3 are required;
unavailable confinement refuses before starting the child. Git requires a
narrow exception: a pinned `/dev/null` O_PATH descriptor, fstat-verified as
character device 1:3, allows only read/write (no truncate/create/remove/rename).
Builds have no device exception. Installed tool executables are trusted.
Repository-local configuration grants no authority to execute programs. Filters
selected for any tracked path via attributes refuse explicitly. Cleanliness
compares raw bytes/executable bits to tree objects plus staged/untracked metadata;
no clean/smudge, textconv, external diff, fsmonitor or hook is run.

Set TMPDIR to a private, disposable directory. Each Git child gets private
`release-git-*` scratch; builds use `release-build-*` scratch for HOME, source,
cache, temporary files and binary. Child-created files have no parent-side
creation handles, so are never claimed by cleanup: nonempty scratch is retained
and its path reported. Review then dispose of that scratch separately. The
release target contains only final bundle entries. Unknown inserted entries
are preserved even on failure. A parent/target rename cannot redirect writes.

Pass `-module-cache` with the exact committed dependency versions in its
`cache/download` directory, used as a read-only `file://` proxy. No network
fallback is enabled; missing dependencies fail closed. The build uses
`-modcacherw` for its private extracted module cache, disables workspace/global
Go configuration and checks embedded build settings. Source cleanliness and
HEAD are rechecked before success. Pre-existing targets and inputs are never
removed or rewritten.

The final directory is private (0700), with binary 0700 and release data 0600;
the owner's runbook assigns installation ownership and modes. Exit 0 means the
offline files were assembled, 1 is refusal/build failure, and 2 is CLI misuse.
Child process PIDs are written to stderr. The tool neither invokes sudo/systemctl
nor creates accounts, installs files or starts a daemon. It writes only below
its newly created target.

## Explicit dependency gates

With no `-enrollment`, enrollment.json is omitted. A supplied path must pass
all regular-file checks and the actual enrollment pin-config parser. Invalid,
unknown, duplicate and aliased members refuse; no syntax-only substitute is used.
Offline parsing does not load the referenced Git registry, establish file
protection, verify a snapshot or perform operator reconciliation. Those remain
protected-runtime enrollment checks. Supply the pin configuration for the
runbook's enrollment copy; omission does not qualify that step.

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
touch no system installation paths. Real positive builds with and without
enrollment run offline and check their manifests with `sha256sum -c`, then
confirm a bounded corruption makes that command exit 1 naming the changed file.
Refusal tests preserve inputs and existing targets. Narrow commands and the twelve overlay controls are in the root README.
No formal attack-surface table was supplied in this brief. These packaging checks
do not qualify deployment, multi-UID behavior or the unavailable dependencies.

The existing mutation runner's optional packaging group plants twelve bounded
weakenings; the eighteen core controls, native subset and five registration
controls are retained. A plant is killed only
by exit 1 and its named test plus intended behavioral witness, not a build/setup
error. Negative witnesses have nearby valid controls.

| Mutant | Narrows the gate to | Named failing test |
| --- | --- | --- |
| packaging-dirty-tree | Rejecting tracked modifications before bundle creation | TestReleaseDirtyTree/tracked |
| packaging-unit-drift | Exact unit equality, including a changed UMask | TestReleaseUnitMatchesSpec/modified |
| packaging-enrollment-policy | Real pin-policy validation rather than syntax-only acceptance | TestReleaseEnrollmentGate/revision |
| packaging-output-path | Anchored exclusive output writes during link substitution | TestReleaseOutputSymlink/true |
| packaging-replacement | Both Git replacement guards remain enabled | TestReleaseReplacementCommit/true |
| packaging-tree-hash | Verify actual exported tree before compilation | TestReleaseExportTreeMismatch/true |
| packaging-child-write | External build descendants cannot write through an escaping link | TestReleaseChildWriteBoundary/true |
| packaging-recursive-cleanup | Unknown contents are never treated as owned creations | TestReleaseCleanupCreatedOnly/unrelated |
| packaging-root-verification | Nonempty adopted roots refuse untouched | TestReleaseAdoptedRoot/nonempty |
| packaging-git-boundary | Every Git child is confined before exec | TestReleaseGitPreflightBoundary/true |
| packaging-filters | Conversion filters are explicitly refused | TestReleaseConfiguredFilters/attributes-file |
| packaging-null-rdev | Null-device exception requires character device 1:3 | TestReleaseNullDeviceVerification |


These witnesses do not claim exhaustive mutation coverage. Surviving or unapplied
plants make the runner fail; they cannot be reported as killed.
