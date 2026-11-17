# Linux pre-releases (test profile)

The [workflow](../.github/workflows/release.yml) produces a **PRE-RELEASE draft**
with the existing offline Keymaker bundle on native Linux amd64/arm64, `SHA256SUMS`,
`provenance.json` and the canonical `release-set.json` fragment. The optional
bot checksum signature is labelled exactly:

> agent-held key, proves nothing about origin

The bot key is available to agents. Neither that key, a tag signature, nor a
checksum signature establishes product origin or release authority. Installer v0
trusts **only the digest of the aggregate release-set manifest**, listing every
artifact digest. The owner approves that one digest **in person before any root
step** (OD-3 plan digest). Two independent reads of each release PR must compare
artifact digests with a second independent build before assembling that set.
The helper below supplies a rebuild comparison, not either review verdict or the
owner's approval. A dedicated release key outside agent sessions remains an
owner key-custody decision (OD-2).

## Book and specification boundary

The Swarma installation book's
[Trust: signatures, manifest, notarization, package channels](https://github.com/relux-works/swarma-docs/blob/main/install-book/ru/04-doverie.md)
chapter describes component signers and a manifest selecting artifact digests.
**Same:** artifact digests belong in the release-set manifest.
**Conflict resolved by the binding interim test-profile ruling:** the shared bot
key cannot supply the book's component trust root; use the owner's in-person
approval of the aggregate set digest until dedicated custody is decided. This
interim profile does not implement the book's future update-key roles.
[Keymaker specification §12](../spec/keymaker.md#12-privileged-linux-step-operator-handoff),
[packaging contract](../packaging/README.md) and
[release recipe](../packaging/RELEASE.md) retain separate operator and runtime
qualification gates; artifact delivery cannot activate Keymaker.

## Default-branch workflow and admission

GitHub loads a tag-push workflow from the tag itself. This template therefore
has **no tag-push trigger**. After pushing a tag, an authorized operator dispatches
`release.yml` **on main**, passing the tag as data. Both jobs require the dispatch
ref and repository default branch to be `main`; both check out `main` with full
history. The draft job requires the identical policy commit used by the build.
If the repository renames its default branch, revise this contract first.

```bash
# After the release controls have landed on main:
git tag -s v1.2.3 -m 'Test pre-release v1.2.3'
git push origin refs/tags/v1.2.3
gh workflow run release.yml --ref main -f tag=v1.2.3
```

Configure a repository **v* tag ruleset** restricting creation, update and deletion
to the authorized release role. Check that setting when adopting this template;
the workflow cannot establish that external setting. Repository workflow/ruleset
administration remains an owner boundary. An independently modified workflow on
a malicious tag is not an execution authority for this main-dispatched flow.
GitHub writers can still create arbitrary release records; the independent build
and owner-approved aggregate digest remain necessary.

[release-admit.sh](../.scripts/release-admit.sh) resolves its policy root from its
own location, requires that checkout at `origin/main`, and refuses local changes
in `.scripts`, `.github/release` or `.github/workflows/release.yml`. It requires:

- An ASCII `v` plus digit tag name, then letters, digits, `.`, `+` or `-`.
- An annotated SSH-signed tag directly targeting a commit, with the internal
  tag name equal to the requested name; lightweight and unsigned tags fail.
- The commit to be an ancestor of `origin/main`. Shallow history and grafts fail;
  replacement objects are ignored. An ancestor can be released, so there is no
  rollback protection.
- The tagged tree's entire `.scripts`, `.github/release` and release workflow
  content/modes to equal the default branch. This intentionally refuses older
  tags whose release controls differ, including a changed admission script or
  allowlist. No script from the tagged tree is executed to admit or build it.
- The tag object and commit to match supplied bindings when present.
- SSH verification using **main's** [allowed_signers](../.github/release/allowed_signers),
  without ambient GPG fallback. This file is **only for TAG verification as a
  consistency check**, under principal `release-tag`, namespace `git`; it is
  **not a trust root**. It is never used to authenticate checksum files.

All actions use full SHA pins. Build has `contents: read`; only draft creation
has `contents: write`. Checkout does not persist credentials. No CI signing key,
OIDC or external signer is configured. Draft creation uses the automatic
`github.token`, not an operator key. Immediately before creation the job rechecks
remote main and tag objects, repeats main's admission and validates the artifact
set. Existing releases are refused; assets are never overwritten. GitHub cannot
atomically bind release creation to ref movement; operator rechecks and the
aggregate owner approval remain required.

## Reproducible build and metadata

[release-build.sh](../.scripts/release-build.sh) requires Go **1.26.10**, a clean
source checkout and native Linux amd64 or arm64. Its optional second argument is
an absolute source checkout. The executable wrapper and `tools/release-bundle`
remain in the current default-branch policy checkout. The wrapper invokes that
existing assembler with the admitted source commit, source version, committed
`packaging/config.example.json` and the inert
[example name registry](../.github/release/name-indices.json).
These are public test-profile inputs, not deployment configuration or live pins.
No Actions secrets are needed. The assembler's source/tree/unit checks, private
empty build cache, offline file proxy, Landlock confinement, flags, native version
execution and bundle SHA256SUMS remain unchanged. There is no second binary build
recipe in this workflow. `packaging/RELEASE.md` remains the existing independent
recipe-equivalence control, not an additional workflow build path.

The [native runner matrix](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
uses `ubuntu-24.04` (amd64) and `ubuntu-24.04-arm` (arm64). It preserves the existing assembler tests on each architecture.
Inventory of `cmd/` main packages:

| Package | Bundle disposition |
| --- | --- |
| `github.com/relux-works/swarma-keymaker/cmd/keymaker` | Existing bundle binary; amd64 builds, arm64 has the source gate below. |
| `github.com/relux-works/swarma-keymaker/cmd/keymaker-window` | Builds on Linux amd64/arm64; existing nonroot integration test harness, not a bundle member. |

The imported baseline `2cc4a390984128437e806a45168eabd55667857a` has an
arm64 compilation gate in `internal/enrollment/files_linux.go`: `Stat_t.Nlink`
is `uint32` there, while `Metadata.Links` is `uint64`. The arm64 job fails closed
until a source portability correction is reviewed. The wrapper does not bypass
that source gate or publish a partial architecture set.

The binding owner instruction to wrap the existing bundle supersedes the original
all-command build step. The harness is not added to the bundle. No darwin output
is produced. The nested `messageauthor` module keeps its **Go 1.26.8** declaration
and root-local `replace => ./messageauthor`; source export includes the nested
module. The root and assembler use Go **1.26.10**.

Each assembler emits `keymaker`, `config.json`, `name-indices.json`,
`swarma-keymaker.service`, `VERSION.json` and `SHA256SUMS`. No systemd unit is
changed or service installed. The wrapper verifies the bundle list and packages
these exact bytes in `swarma-keymaker-bundle_linux_ARCH.tar`, a sorted USTAR with
numeric uid/gid zero, empty owner names, fixed modes and the source commit's
committer timestamp as `SOURCE_DATE_EPOCH`. No workstation identifiers enter
release metadata. Archive creation does not rebuild a binary.

`bundle-SHA256SUMS_linux_ARCH` preserves the assembler's list byte for byte.
`provenance_linux_ARCH.json` contains the assembler's actual `VERSION.json`
record (commit, verified exported tree, version, Go version, OS/architecture and
trimpath), plus the archive epoch. It makes no invented claim about settings not
recorded by the assembler. It is input evidence, not an origin attestation.
`SHA256SUMS_linux_ARCH` covers that archive, original bundle checksum list and
native provenance; `release-set_linux_ARCH.json` binds those and the native list.
Native checksum signatures therefore cover a complete bundle for one architecture.

The draft job requires both architectures with identical source commit/tree,
version and epoch. It creates `provenance.json` from both bundle records and a
sorted top-level `SHA256SUMS` covering both archives and every native metadata
file. The canonical `release-set.json` binds all of those plus `SHA256SUMS` for
incorporation into the installer's aggregate release-set manifest. The fragment
cannot hash itself; optional native checksum signatures are ancillary consistency
evidence, not installer inputs. JSON uses sorted keys, sorted artifact names,
ASCII, compact separators and exactly one trailing newline. The fragment is an
interchange fragment, not an implemented installer schema.

For local checks, use two independent physical source checkouts at the same
commit and toolchain **on each native architecture**. Resolve absolute scratch
paths before Go; place `HOME`, `USERPROFILE`, `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`,
`TMPDIR`, `TMP`, `TEMP`, `GOTMPDIR`, `GOCACHE`, `GOMODCACHE` and `GOPATH` under
owned scratch, and unset `GOTELEMETRYDIR`. Populate the exact dependency download
cache first. Optional `RELEASE_MODULE_CACHE=/absolute/cache` seeds downloads from
its read-only file proxy without network fallback. Every assembler build still
uses fresh private extracted modules and an empty private build cache.
The hosted workflow seeds the default module cache with a verified `go mod download`
before the controls; the offline build then reads only that seed.

```bash
GO=/absolute/path/to/go1.26.10/bin/go .scripts/release-build.sh \
  /absolute/scratch/dist /absolute/scratch/source
cmp /absolute/first/dist/SHA256SUMS /absolute/second/dist/SHA256SUMS
cmp /absolute/first/dist/release-set.json /absolute/second/dist/release-set.json
```

The output directory must not exist. Matching hashes establish reproducibility
for that pair of native builds, source and environment; they do not establish
origin. Workflow and signing helper create isolated absolute home/config/cache/
temp directories automatically. The bundle requires Linux `openat2` and Landlock
ABI 3 or later and fails closed if either is unavailable.

## Independent operator rebuild and optional bot signature

Use the trusted current-main checkout, not a downloaded script or the tag tree.
The operator's GitHub CLI needs release-write access. Run the helper
independently on **each native architecture**. It fetches main
and the requested tag without forcing a moved tag, then runs main's admission.
It requires a draft marked pre-release and the exact bot-key label in its body.

```bash
GO=/absolute/path/to/go1.26.10/bin/go .scripts/release-sign.sh v1.2.3
# Optional repository argument when adopting the template:
GO=/absolute/path/to/go1.26.10/bin/go .scripts/release-sign.sh v1.2.3 OWNER/REPO
```

[release-sign.sh](../.scripts/release-sign.sh) copies the admitted tag to a fresh
source checkout and independently rebuilds under `.temp/release-sign.*`, with
fresh absolute home/config/cache/temp paths. It compares the local canonical
`SHA256SUMS_linux_ARCH`, `provenance_linux_ARCH.json` and
`release-set_linux_ARCH.json` byte for byte with the pre-release. **Any
mismatch refuses before signature creation or upload.** This compares every
artifact digest in that native bundle with a second build. The other
architecture requires its own native run; a single run does not verify the
complete two-architecture aggregate. It then rechecks admission, remote tag/main
and draft state, signs
**the local rebuilt** `SHA256SUMS_linux_ARCH` using `git config user.signingkey`, uploads
without clobbering, and verifies byte-identical readback of the signature and
metadata. The uploaded file is `SHA256SUMS_linux_ARCH.sig`. The signature is
ancillary; the tag-only allowlist is not consulted
for checksum verification. The helper does not publish or approve a release.
Evidence is retained. Concurrent external publication cannot be prevented by
these CLI checks.

After both required release PR reads compare independent build digests, assemble
the aggregate release-set manifest and obtain the owner's in-person approval of
its digest before any root step. Publishing the pre-release is an explicit
operator action; retain the pre-release flag:

```bash
gh release edit v1.2.3 --repo relux-works/swarma-keymaker \
  --draft=false --prerelease
```

## Artifact consistency check

Download the bundle archives and all metadata into a fresh directory. Use a
separately
obtained expected **fragment** digest from the reviewed aggregate manifest:

```bash
.scripts/release-verify.sh /absolute/assets EXPECTED_FRAGMENT_SHA256
```

[release-verify.sh](../.scripts/release-verify.sh) and
[release-metadata.py](../.scripts/release-metadata.py) check the supplied fragment
digest, canonical fragment/list, each artifact digest, mandatory provenance and
bundle entries, preserved inner lists, native provenance and archive members.
Traversal, duplicate entries, mismatched bundle provenance and symlinks fail.
This establishes consistency with the supplied digest, not origin, freshness,
owner approval or runtime qualification. Fetching the expected digest from the
same release supplies no independent approval. The installer must verify the
owner-approved **aggregate** digest and its entire selected artifact set.

## Controls and adoption

```bash
actionlint .github/workflows/release.yml  # If installed; otherwise report missing.
for script in .scripts/release-*.sh; do bash -n "$script" || exit; done
# Under the same private absolute TMPDIR: inert metadata controls only.
python3 .scripts/release-metadata-test.py
GO=/absolute/path/to/go1.26.10/bin/go .scripts/release-test.sh /absolute/new/scratch
```

The scratch test owns its empty home/config/caches, Git repositories and ephemeral
keys, with ambient signing config and SSH agent disabled. Real Git/SSH objects
exercise main/ancestor admission and lightweight, unsigned, inconsistent,
tampered, renamed, off-main, binding and dirty-policy refusals. On-main ancestor
tags that replace admission or its allowlist must fail beside a valid tag.
Real assembler builds exercise reproducibility, canonical metadata, changed archives,
traversal, duplicates and symlinks. A local GitHub CLI double exercises off-main,
mismatched-digest, missing-label and non-prerelease refusals, plus rebuild/sign,
readback and no-overwrite controls. This is not hosted workflow evidence.
Seven additional inert archive/record controls test both-architecture combination,
source/tree/epoch agreement, inner checksum integrity, provenance correspondence
and link/traversal refusal. These are metadata fixtures, not native arm64 build
evidence. No Keymaker seed, daemon or live release API is touched by the tests.

When adopting this port, include `.scripts/release-*` (including the Python 3
metadata helper), workflow and docs. Change the repository default in the signing
helper, install the public **tag consistency** pin, verify the v* tag ruleset,
land controls on main, and run scratch controls plus two independent full builds.
Preserve the interim owner-approved aggregate trust boundary. Dedicated key
custody and runtime qualification remain separate owner gates.
