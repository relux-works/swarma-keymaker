# Internal certification artifact codecs

These are S2's closed persisted codecs, not native request formats. The schema-2
inventory is specified in [the state contract](../spec/keymaker-msg-state.md).
All newly written artifacts use the existing integer-only CCJ-1 encoder in
`internal/keymaker/audit.go`. Reading checks the complete member set, types,
canonical bytes, byte length and SHA-256. No omitted member acquires a default.
Nullable members are present as `null`; empty inventories are `[]`, never null.
Integers are exact safe integers. Original envelope bytes are canonical unpadded
base64url; hashes are 64 lowercase hexadecimal characters. Internal transaction
IDs are 32 lowercase hexadecimal characters and never recycled.

The implementation types are in `message_attestation.go`, `message_state.go`
and `message_reconcile.go`, under `internal/keymaker/`.

| Object | Exact members and types |
| --- | --- |
| Artifact reference | `{hash:string,bytes:integer}`; bytes is 1 through 256 MiB, and both fields match the complete retained file |
| Message binding | `{uid:integer,generation:string,registration_number:integer,master_epoch:string,owner:string,path:string}`; UID 0–4294967294, registration 1–9007199254740991, nonempty UTF-8 association strings at most 255 bytes, purpose-4 hardened sibling path |
| Issuer policy | `{path:string,key:string,master_epoch:string,registry_revision:string,lifetime_seconds:integer}`; independently selected purpose-5 tuple and Ed25519 key ID, protected epoch/revision, lifetime 1–86400 seconds |
| Certificate | `{transaction:string,binding:MessageBinding,key_id:string,issuer_policy:IssuerPolicy,envelope:string,content_id:string}`; recompute attestation body ID and verify the complete fixed signed record, policy and six-field association |
| Intent | `{binding:BaseBinding,issuer_policy:IssuerPolicy,key_id:string,issued_at:string,reserved_bytes:integer,base_version:integer,base_digest:string,previous_current:string-or-null}` |
| Candidate | `{certificate:Certificate,intent:ArtifactReference,effect:CandidateEffect}` |
| Candidate effect | `{binding:MessageBinding,base_version:integer,base_digest:string,current:string-or-null,pending:string,phase:string,publication:ArtifactReference-or-null}` |
| Resolution | `{outcome:string,intent:ArtifactReference,candidate:ArtifactReference-or-null,version:integer,digest:string}` |
| Migration decision | `{from_schema:integer,to_schema:integer,base_version:integer,base_digest:string}`; exactly 1 to 2, paired to the complete validated original legacy snapshot and its journal commit |

`BaseBinding` is the unchanged closed binding row from the base profile, including
the purpose-1 path, registrar principal, lifetime, status and registry revision.
It is retained in full; the message association does not replace it. The intent
timestamp uses exactly `YYYY-MM-DDTHH:MM:SSZ`. It fixes the issuance time/lifetime
before signing. Preparation may not shift that time to extend the window.
`previous_current` and effect `current` refer to an exact certificate transaction.
The candidate includes its original intent reference, exact certificate and
explicit proposed effect against that intent's base version/digest. It has no
self-reference or reference to a future snapshot hash.

S2 accepts only candidate effect `phase:"issued"`, `pending` equal to its own
transaction ID, `current` equal to the retained predecessor, and publication
null. An issued candidate is evidence, not activation. S2 has no qualified
current certificates or publication records: serving validation rejects non-null
current and nonempty publication inventories. Publication, active and closed
phases require later qualified integration; there is no timeout-based clearing.

Resolution outcome is `aborted` or `issued`. Its version/digest identify the
exact complete state preceding that resolution, independently matched to the
journal. Aborting is permitted only before issuance commit. An issued resolution
preserves pending. Retries do not write another resolution or sign a certificate.
Every fence, issuance and resolution event is matched to its exact artifact,
resolved binding and adjacent snapshot commit interval. Audit uses the existing
closed fields, without envelopes, signatures or new JSON members.

Files reside in protected `message-tx/<id>/`: immutable artifacts are named by
their SHA-256. Every committed state body also has an immutable
`snapshot-<version>` copy whose hash equals that version's `binding_commit`
digest. The body omits only its own audit sequence/hash. The installed snapshot
includes that linkage. Migration retains the original, unchanged legacy bytes
as `message-tx/migration/base`, plus its canonical `decision` and recovery copy.
File creation uses O_EXCL, file sync and directory sync before committing any
reference; unknown/conflicting staging is preserved and fences recovery.

The shared 256 MiB budget charges encoded artifacts, all retained recovery
copies, installed/staged snapshots and a 4 MiB proof reservation per pending
association. Admission conservatively checks eight prospective base-body copies
plus 8 MiB, the actual installed snapshot and existing artifacts/reservations
before the intent. The intent
records its transition reservation of eight base-body copies plus 4 MiB. All
subsequent writes recheck capacity. Every snapshot transition reserves its new
immutable recovery body and complete install staging before writing either or
appending the journal commit. The encoded bound includes the maximum audit
sequence/hash linkage. The native `fitsState` preflight additionally reserves
both intent/effect recovery copies and their installation peak. Migration sizes
the retained original legacy bytes and decision before writing; reconciliation
sizes its complete resolution, artifact and snapshot copies before writing.
Capacity refusal leaves the journal and installed state unchanged, and startup
checks existing inventory without requiring space for another transition.
Journal control headroom is separately
earmarked for eight maximum-size audit records; unrelated appends cannot spend
that ticket. Insufficient capacity never evicts evidence. The S4/S5 runtime successor must qualify the
actual separate journal/freshness/prior/witness bounds against these reservations and stays closed
when they are insufficient.

PENDING: protected floor deployment and exclusion of older/restored servers,
root provisioning and multi-UID integration; bounded time authority outside
generation windows and conservative Now/W mapping; owner-registry/WC1 transport,
S4/S5 freshness/receipt adapter and explicit successor-codec migration,
qualified-T1 renewal and activation. The current closed schema-2 reader must
not accept these new artifact/state shapes by adding optional members. These
codecs supply no administration CLI or production constructor.
