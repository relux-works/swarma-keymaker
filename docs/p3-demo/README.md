# P3: source-only demo recipe for precreated station accounts

This is an **unexecuted operator handoff**, for two or three accounts already
created by the VM operator. No VM, installation, enrollment, release, key or
signature is produced by these files. The demo is **NOT QUALIFIED** until the
real VM exists and its operator has supplied and verified the evidence below.
The planner prints JSON instructions only; it never executes them.

The assigned release inputs are:

| Component | Exact source for the intended `v0.1.0` tag | Expected Linux amd64 binary |
| --- | --- | --- |
| Keymaker | `a713cc346db980e0a97affe3e5466d2ca4dc60b0` | 7,365,001 bytes; owner-supplied digest prefix **`f336ee8c` only** |
| Registrar | `4494323068bb969a0c3c14b2e44e174217fc7c56` | 11,668,143 bytes; `8b3c3f18d71a8350de406e6dae2bf58d9073c0af371c5143d61cadac4cde2e7b` |

Release **option B**: build from verified signed source; no published binary.
The release tag signer must be **Ivan's platform release key, explicitly named
by Ivan or the authorized lead**. Its identity/fingerprint is still missing.
An agent commit key, Relux Zion's key and curator-spec allowed signers confer no
platform release authority. This unit creates neither tag nor release.
The Keymaker source recipe contains a candidate full digest, but this handoff
does not promote it to an owner-approved W0 pin. Obtain the full approved
64-hex digest; prefix comparison alone must never permit installation.

## Before the VM operator starts

The operator must supply the following public references and protected inputs.
Record identifiers and hashes of public configuration/evidence; never export
seeds, private keys, tokens, raw signed acts or live credential payloads.

1. The real VM, operator approval for this demo, an identified root operator,
   and two or three **operator-precreated** station accounts. Pin their distinct
   nonzero UIDs, names, current journal generations, homes and private workspace
   copies. Homes are 0700 and owned by their station; workspaces are private
   children. No station receives another station's writable checkout or cache.
   The configured operator UID/generation is distinct from station UIDs.
2. Ivan's explicit platform release-key binding; verified `v0.1.0` tag signatures
   against that independently trusted key, and peeled targets equal to both
   exact commits above. Do not replace an existing tag, infer a signer from
   curator-spec, or use this docs PR's signer as the release key.
3. Two independent clean builds of each release, official Go **1.26.10**,
   fresh private caches, committed dependency versions and canonical `h1`
   verification. Follow [Keymaker's exact release recipe](../../packaging/RELEASE.md)
   and Registrar's `docs/release-v0.1.0.md` at the exact Registrar commit above.
   Verify full digests and sizes; preserve both build logs, times and exits.
   Require completed `govulncheck@v1.1.4` evidence with zero called vulnerabilities
   for each approved tag. No dependency upgrades or substitution of Registrar
   main for Keymaker's committed module dependency is authorized here.
4. The protected service config, name-index registry and service layout from
   [section 12.1](../../spec/keymaker.md#121-explicit-preflight-and-dynamic-service-ids).
   Replace every example ID/epoch/revision. The service remains a dedicated
   unprivileged identity; its allocator is separate from station provisioning.
   Verify root-protected ancestors, group access, private state, seed custody,
   socket modes and independently qualified time policy. A parsed config or
   copied service unit alone establishes none of these facts.
5. W0 gate **(i)**: user-manager's authoritative generation journal writer, or
   the qualified **rw4 root-run procedure in that same format**. For this VM
   demo, the operator may manually record the precreated accounts using that
   procedure. Preserve the procedure/version, actual UID/generation rows and
   verified journal floor/revision. A hand-written account inventory, passwd
   lookup or synthetic fixture journal is insufficient. Record `retiring` or
   `removed` with the required ordering before account removal; a late entry
   provides no retirement fence. This recipe does not invent a writer command.
6. W0 gate **(j)**: Ivan's first signed enrollment commit, independently verified
   publisher/maintainer pins, explicit Git object format and full revision,
   protected operator approval file, and exact `uid_map` rows for the selected
   stations. Registrar owns these formats. `uid_map` is an array of objects:
   each UID is unique, each allowed name is exact and covered by the enrollment,
   and different UIDs cannot claim the same name. Keymaker rejects `exe` rows
   as unsupported; omit `exe` for this cut. Root-controlled `stations` and
   `generations` pins must agree with the signed enrollment and journal.

The VM demo exception for manual Q6 recording does not open production enable.
Production stays gated on **(b), (i), (j), (l)** and the remaining source
qualification requirements; no meaning or pass result for (b)/(l) is inferred
here. P2 dispatcher belongs to its separate lane; P4 broker remains on hold.

## Dry-run intake

Use `manifest.example.json` as an intentionally incomplete public inventory.
Null values mean missing inputs. Fill it only with public references, hashes,
numeric identity pins and paths, never secret contents. The planner does not
open any referenced file, inspect accounts or verify any evidence reference.

```sh
python3 docs/p3-demo/plan.py docs/p3-demo/manifest.example.json
```

Exit **3** means missing inputs, with an empty step list. Exit **2** means bad
JSON/schema/pins or invalid CLI usage, with no input values echoed. Exit **0**
means an **unexecuted plan** was produced; it grants no authority and always
reports `qualified: false` and `evidence_authenticated: false`. A plausible
evidence string is not proof. Keep the JSON plan private to the operator and
review every reference and protected inode independently before any live step.
The parser caps input at 65,536 bytes and accepts only the closed template.
Select `enrollment.mode` explicitly: `bootstrap` requires independent evidence
of genuinely empty first-use state; `reconcile` is for all later starts. The
required `state_evidence` reference records that operator inspection. It is
never inferred from a fresh VM name or the presence of station accounts.

## Installation and enrollment, later on the authorized VM only

1. Stop before any mutation if an input above is missing. Verify the full
   hashes, sizes, tag signatures and exact tag targets. Copy the verified bundle
   into root-controlled `/var/tmp/keymaker-release`, with no station-writable
   ancestors. Use the pinned section 12.1 runbook verbatim for service name/path
   collision checks, service-only ID allocation, state/seed protection, binary,
   config, name registry, enrollment pins and systemd unit installation. It
   aborts on existing paths and lookup errors. A partial installation needs
   operator inspection; do not retry by weakening guards. The station accounts
   are already present; do not run section 12.2 account/sudoers provisioning.
2. Install the independently approved enrollment pins at the **same path** used
   by `registration_helper.enrollment_config` (the original section 12.1 example
   uses `enrollment.json`, while the helper example uses `enrollment-pins.json`;
   reconcile this explicitly before staging). Keep `approval_file` bound to the
   approved protected input. Do not confuse that helper policy file with the
   command's one-use reconciliation receipt. The operator supplies both as
   required by the selected landed helper/startup policy.
3. With the helper/service stopped, use the real Keymaker CLI. There is no
   `keymaker enrol` or Registrar enrollment-publisher CLI in these releases:

   ```sh
   # Root operator, initial acceptance ONLY; state directory must be truly empty.
   /usr/local/bin/keymaker enrollment reconcile --config "$ENROLLMENT_CONFIG" --bootstrap
   # If an independently approved complete state digest is already available:
   /usr/local/bin/keymaker enrollment reconcile --config "$ENROLLMENT_CONFIG" --bootstrap --confirm "$EXACT_STATE_SHA256"
   # Every later restart uses normal reconciliation, never another bootstrap:
   /usr/local/bin/keymaker enrollment reconcile --config "$ENROLLMENT_CONFIG"
   ```

   The first two lines are **alternatives**, not a sequence. Independently check
   the displayed pin, publisher, audience, full revision, hosts and complete
   `state_sha256` against current approved evidence. Merely hashing local state
   establishes no freshness. Require the command's **exit 0** and final approved
   report. An `approved` object before a later failure is insufficient. Preserve
   orphan/fence/partial state on failure; never delete evidence to re-bootstrap.
   The command creates a one-use receipt for the **default** enrollment startup
   reconciler. That default reconciler consumes it; every restart needs a new
   decision. The actual `serve` helper uses the distinct explicit adapter below.
4. Only after a separate operator GO and the W0/runtime gates, systemd may run
   `/usr/local/bin/keymaker serve --config /etc/swarma-keymaker/config.json`
   **as the service UID**, never root. Missing journal or trusted time must
   remain a refusal. The original service's production `enable --now` gate is
   preserved; this document does not authorize it or auto-start anything.
   Registrar's actual command is `registrar serve --config <path>` (normal
   protected TLS/time/audit configuration); `--reconcile` is an explicit
   rollback-reconciliation choice, never an unattended success switch.
   No live registrar/Matrix admission is needed for the Git signature demo.
5. The exact landed `serve` helper calls `NewOperatorReconciler(approval_file)`
   and supplies it explicitly to `enrollment.New`; it does **not** consume the
   command's default one-use receipt. Observe the live process's public
   `enrollment startup challenge` in the operator's protected status channel.
   After independently reconciling current approved pins, full state digest and
   history, the root operator publishes a protected approval file containing
   exactly `{"startup_id":"<that live challenge>","state_sha256":"<independently approved full digest>"}`
   at `registration_helper.approval_file`. These strings are placeholders,
   never fabricated by this recipe. Root-protected, nonsymlink ancestors/file
   and no group/world write are required. Operator-controlled SIGHUP retries
   loading with the same challenge; require helper success, not just socket
   readiness. A new process gets a new challenge. Missing/wrong approval keeps
   helper authority fenced. CLI receipt success alone does not open it.

## Bind each account and demonstrate its own signature

There is **no Keymaker register/sign CLI**. Use a reviewed operator native
client on `/run/swarma-keymaker/control.sock`, authenticated by the configured
operator's actual kernel UID and current generation. For each station it sends
hello, waits for success, then sends `register` with exactly `target_uid`,
`target_generation`, `owner`, `names` and `lifetime`. Names must resolve in the
approved registry and `purpose` is `agent-identity`; this recipe selects
`persistent`. Persist the original request IDs/arguments/results before retry.
The planner's illustrative IDs must be replaced with fresh recorded live IDs;
never replay those constants in another run. Retry uncertain effects with the
**same** ID/arguments after investigation, not a new registration request.

The native wire is a four-byte big-endian body length followed by one CCJ-1
canonical JSON body (1–65,536 bytes). Hello is
`{method:"hello", request_id:<32 lowercase hex>, versions:[1]}`; subsequent
requests have exactly `{method,params,request_id,timeout_ms}` with timeout
1–2000 ms. Send only one in-flight request per connection; check every correlated
response/error and bound the frame/read time. Never send a native `sign` method
or SSH packets to this socket. The planner emits message *values*, not a socket
client or live-ready frame stream; the fake checker round-trips bounded frames
only for its ASCII fixtures, not a general CCJ-1 implementation.

As each actual station UID, use native `pubkey` with empty params after hello
to read its own bound public identity. The response's `public_key` is standard
base64 of **32 raw bytes**. An OpenSSH public-key file requires the SSH key blob:
`uint32be(11)||"ssh-ed25519"||uint32be(32)||raw_public_key`, then standard
base64, prefixed by `ssh-ed25519 `. Do not put the raw 32-byte encoding directly
into Git's selector. The operator independently verifies the binding/path/
registration number/epoch and installs only this **public** `.pub` selector.
No seed, private key or ordinary host SSH-agent socket is used by the demo.

In that station's private disposable Git workspace, set explicit local author
identity and use stock Git/OpenSSH. Git supports a public-key file as its SSH
signing selector when the private key lives in the selected agent:

```sh
SSH_AUTH_SOCK=/run/swarma-keymaker/agent.sock \
git -c core.hooksPath=/dev/null -c gpg.format=ssh \
    -c user.signingkey="$BOUND_PUBLIC_KEY_FILE" \
    commit --allow-empty -S -m 'P3 isolated VM demo'
git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile="$INDEPENDENT_ALLOWED_SIGNERS" \
    verify-commit HEAD
```

The verifier's allowed-signers file must already trust the independently
approved station key/principal; successful signing must not manufacture trust.
Preserve exact commit ID and verification result privately. Repeat for both or
all three accounts. A missing or mismatched binding must fail; another station's
public key must be refused. Preserve the valid own-key control adjacent to a
foreign-key refusal, including bounded times and real exits. Do not swap UIDs,
copy keys or install a fixture adapter to force success. Existing multi-UID
fixture tests/window compilation are separate evidence and do not qualify this
installed demo. Persistent revoke remains gated by signed-act integration;
do not invent an unsigned cleanup/revoke path. Stop the dedicated demo service
under operator control and retain state/evidence for inspection.

## Offline source checks

`check.py` uses only Python's standard library and inert fabricated public
manifest values. It does not import product packages, build binaries, generate
keys, start services, read credentials, access sockets or invoke subprocesses.
It checks missing-input refusal, 2/3-account plans, invalid identity/pin/schema
inputs, bounded JSON/framing and the real CLI/native-source anchors. The fake
full Keymaker hash in its fixture is **not** a release pin or exported manifest.

Run it under the workbench's offline `bwrap --clearenv --unshare-all` boundary,
mounting this source at `/src` and the exact Registrar source read-only at
`/registrar`, with only read-only system Python/tools and private 0700 absolute
HOME/TMP/cache directories. Do not expose host home, agent/key sockets,
credentials, network or foreign caches. From `/src/docs/p3-demo` run
`python3 -S -B check.py` with a 45-second outer timeout and 30-second CPU limit.
No public dependencies are downloaded or changed by these checks. A pass
validates this source recipe/planner, not W0, cryptography, live UID separation,
time confidence or installed enrollment.

Source anchors: Keymaker `cmd/keymaker/main.go`,
`internal/keymaker/native.go`, `internal/keymaker/runtime_linux.go`,
`internal/enrollment/README.md`, `spec/keymaker.md` §§3,5–8,12.1;
Registrar `cmd/registrar/main.go`, `spec/registrar.md` §4.2 and
`docs/release-v0.1.0.md`, all at the source pins above.
