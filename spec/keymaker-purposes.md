# Numeric purpose catalog

This is Keymaker's authoritative numeric allocation/reservation catalog.
Numbers refer to key derivation namespaces, not wire profile strings, native
method registration, name-registry indices, service roles or activation.
Existing domain/profile contracts remain authoritative for their signed bytes.
The legacy `Registry.Resolve` API still admits only purposes 1 and 2; station
bindings and Surface A still admit only purpose 1. A row never widens them.

| Number | Name | Key/custody and signed scope | Allocation/reservation and implementation status | Source contract |
| --- | --- | --- | --- | --- |
| 1 | `agent-identity` | Legacy Ed25519, bound Git SSHSIG subset | Existing fixed allocation; peer-bound legacy surface | [Base §4](keymaker.md#4-derivation-and-storage) and `internal/keymaker/derive.go` |
| 2 | `host-registration` | Legacy Ed25519, configured registrar-built registration proof | Existing fixed allocation; separate configured helper | [Base helper](keymaker.md) and `internal/registration/README.md` |
| 3 | `state-witness` | Reserved internal `keymaker-witness-record/1` + NUL; no socket key access | Proposal/reservation only; option C activation remains gated | [Witness §3.1](keymaker-witness.md#31-protected-identity-and-purpose-separation) |
| 4 | `swarma-msg` | Ed25519 sibling, fixed `swarma-msg/2` + LF | Reserved message contract; internal key/issuer state exists, native signing unavailable | [Message §§1–4](keymaker-msg.md#1-purpose-registry-and-domain-separation) |
| 5 | `root-attestation` | Ed25519 internal issuer, separately pinned root; service-built agent `attestation/1` only, never revocation snapshots | Decided MSG3 allocation; publication-backed currentness/activation gated | [Message §4.2](keymaker-msg.md#42-landed-s0-attestation-bytes-and-publication) |
| 6 | `station-caller` | Separate proposed typed dispatcher/delegation signing domains | Owner-approved proposal/reservation, **unallocated for implementation/activation**; codec is inert | [Station caller §§1–2, 5, 8](keymaker-station-caller.md) |
| 7 | `j7-request` | Independent secp256k1 root, typed BIP-340 request custody | Allocated source capability; opt-in internal adapter, production startup/native qualification closed | [J7](keymaker-j7.md) |
| 8 | `child-delegation` | Independent secp256k1 root, separate parent allocation/child delegation domain | Allocated source custody namespace; child signing/v4 and production activation closed; configured role name is `delegation` | [J7](keymaker-j7.md) |
| 9 | `message-author` | **Independent secp256k1 root**, exact `swarma-msg/2` BIP-340 author profile | **Allocated fixture-only source capability, not live**; public value codec only, no production constructor/config/route/state participant | [Message author](keymaker-message-author.md) |

Purpose 9 does not reinterpret purpose 4's Ed25519 history or share a root,
instance, key capability or signing route with purposes 7/8. The bound identity
remains `m/1'/product'/project'/agent'`; the private fixture selector changes only
the purpose ancestor to `m/9'/product'/project'/agent'`. All four components are
hardened and name indices positive 31-bit values. No generation hash, caller
path, registry-index reinterpretation or implicit purpose 3/6 activation follows.
No other number is allocated by this catalog. A future allocation requires a
reviewed catalog change plus its owned profile; native/config/state activation
requires its own explicit review and qualification.
