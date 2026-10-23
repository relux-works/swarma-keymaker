package keymaker

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keymaker/internal/control"
	proof "github.com/relux-works/swarma-keymaker/internal/registration"
)

// Every custody cause traverses actual sockets with byte-exact common refusals,
// local bounded cause metadata, and no retained result. Independent open controls
// verify identity/helper signatures or public keys. Fixture ownership/authority
// is used; this does not qualify live multi-UID deployment or memory protection.
func TestCustodyAuditCauses(t *testing.T) {
	for _, surface := range []string{"agent-sign", "agent-pubkey", "control-pubkey", "control-register", "helper"} {
		t.Run(surface, func(t *testing.T) {
			for _, state := range []string{"closed", "nil", "unloaded", "protection_failed", "open"} {
				t.Run(state, func(t *testing.T) {
					b := nativeOwnBinding()
					var f *nativeFixture
					var trust *helperTrust
					if surface == "helper" {
						f, trust = helperSetup(t)
					} else if surface == "control-register" {
						f = nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, nil)
					} else {
						f = nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, &b)
					}
					public, code := f.master.Public(b.Path)
					if code != "" {
						t.Fatal(code)
					}
					seed := append([]byte(nil), f.master.seed...)
					defer erase(seed)
					master := f.master
					cause := state
					switch state {
					case "closed":
						master.Close()
					case "nil":
						master = nil
						cause = "unloaded"
					case "unloaded":
						master = &Master{}
					case "protection_failed":
						master = &Master{seed: bytes.Repeat([]byte{0x42}, 31)}
					}
					f.engine.Signer = master
					if trust != nil && state != "open" {
						builder, err := proof.New(trust.clock, rand.Reader, registrationSigner{master, helperPath})
						if err != nil {
							t.Fatal(err)
						}
						trust.helper.builder = builder
					}
					before := nativeSnapshot(t, f)
					f.start()
					path := f.server.ControlPath
					if surface == "agent-sign" || surface == "agent-pubkey" {
						path = f.server.Path
					}
					c := nativeDial(t, path)
					if surface == "agent-sign" || surface == "agent-pubkey" {
						body := []byte{11}
						if surface == "agent-sign" {
							body = validBody(public, "git")
						}
						if err := writeResponse(c, Packet(body)); err != nil {
							t.Fatal(err)
						}
						raw, code := ReadFrame(c)
						if code != "" {
							t.Fatal(code)
						}
						if state != "open" {
							if !bytes.Equal(raw, []byte{5}) {
								t.Fatal("custody response bytes changed", state)
							}
						} else if surface == "agent-sign" {
							if len(raw) == 0 || raw[0] != 14 {
								t.Fatal("open custody did not sign")
							}
							r := wireReader{b: raw[1:]}
							blob := r.string()
							signed := wireReader{b: blob}
							algorithm, signature := signed.string(), signed.string()
							q, code := parseAgent(body)
							if code != "" || r.bad || len(r.b) != 0 || signed.bad || len(signed.b) != 0 || string(algorithm) != "ssh-ed25519" || !ed25519.Verify(public, q.data, signature) {
								t.Fatal("open custody signature invalid")
							}
						} else if !bytes.Contains(raw, PublicBlob(public)) {
							t.Fatal("open custody public key missing")
						}
					} else {
						nativeNegotiate(t, c, 1)
						before = nativeSnapshot(t, f)
						r := nativeRequest(2, "pubkey", control.Object{})
						if surface == "helper" {
							r = nativeRequest(2, "sign_registration", control.Object{"name": helperName, "aud": helperAudience})
						}
						if surface == "control-register" {
							r = nativeRegisterRequest(2)
							r["params"].(control.Object)["target_uid"] = int64(os.Getuid())
						}
						nativeSend(t, c, r)
						raw, code := ReadFrame(c)
						if code != "" {
							t.Fatal(code)
						}
						if state != "open" {
							want := []byte(`{"error":{"code":"custody_unavailable","retryable":false},"request_id":"00000000000000000000000000000002"}`)
							if !bytes.Equal(raw, want) {
								t.Fatal("custody response bytes changed", state)
							}
						} else {
							obj, err := control.Decode(raw)
							if err != nil {
								t.Fatal(err)
							}
							if surface == "helper" {
								helperResult(t, obj, nativeID(2), "", trust.helper.key)
							} else {
								result := nativeResponse(t, obj, nativeID(2), "")
								if result["public_key"] != base64.StdEncoding.EncodeToString(public) {
									t.Fatal("open custody key invalid")
								}
							}
						}
					}
					rows := nativeAudit(t, f.store.journal)
					last := rows[len(rows)-1]
					encoded, err := json.Marshal(last)
					if err != nil {
						t.Fatal(err)
					}
					var fields map[string]any
					if err := json.Unmarshal(encoded, &fields); err != nil {
						t.Fatal(err)
					}
					if state == "open" {
						if _, ok := fields["custody_cause"]; ok {
							t.Fatal("successful custody wrote a cause")
						}
					} else {
						if last.RefusalCode == nil || *last.RefusalCode != "custody_unavailable" || fields["custody_cause"] != cause {
							t.Fatal("custody audit cause mismatch", state, fields["custody_cause"])
						}
						if !bytes.Equal(before, nativeSnapshot(t, f)) {
							t.Fatal("custody refusal changed retained state")
						}
					}
					allowed := map[string]bool{}
					for _, key := range []string{"seq", "time", "instance", "surface", "request_id", "peer_uid", "generation", "path", "master_epoch", "operation", "domain", "payload_digest", "result", "refusal_code", "custody_cause", "previous_digest", "record_digest"} {
						allowed[key] = true
					}
					for key := range fields {
						if !allowed[key] {
							t.Fatal("unbounded custody audit member", key)
						}
					}
					for _, material := range [][]byte{seed, bytes.Repeat([]byte{0x42}, 31)} {
						if bytes.Contains(encoded, []byte(hex.EncodeToString(material))) || bytes.Contains(encoded, []byte(base64.StdEncoding.EncodeToString(material))) {
							t.Fatal("custody audit disclosed seed material")
						}
					}
				})
			}
		})
	}
}

// The closed enum is required on new custody refusals and forbidden on other
// records. Invalid records append no bytes; each case has a valid closed control.
// Cause-less custody records now refuse recovery; ordinary old records retain
// their unchanged schema/hash (covered by the matrix and existing audit tests).
func TestCustodyAuditSchema(t *testing.T) {
	for _, kind := range []string{"missing", "unknown", "success", "other-refusal", "closed", "unloaded", "protection_failed", "legacy"} {
		t.Run(kind, func(t *testing.T) {
			d := t.TempDir()
			if err := os.Chmod(d, 0700); err != nil {
				t.Fatal(err)
			}
			dir, err := OpenDirectory(d, uint32(os.Getuid()), 0700)
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			j, err := OpenJournal(dir, uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			code := Code("custody_unavailable")
			cause := custodyCause(kind)
			r := AuditRecord{Surface: "agent", Operation: "sign", Result: "refused", RefusalCode: &code, CustodyCause: &cause}
			switch kind {
			case "missing", "legacy":
				r.CustodyCause = nil
			case "success":
				r.RefusalCode = nil
				r.Result = "success"
				cause = custodyClosed
			case "other-refusal":
				code = "binding_not_found"
				cause = custodyClosed
			}
			path := filepath.Join(d, auditName(1))
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			valid := kind == "closed" || kind == "unloaded" || kind == "protection_failed"
			if c := j.Append(r); valid && c != "" || !valid && c != "audit_unavailable" {
				t.Fatal("custody schema verdict", kind, c)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !valid && (!bytes.Equal(before, after) || j.seq != 0) {
				t.Fatal("invalid cause wrote audit bytes")
			}
			control := AuditRecord{Surface: "agent", Operation: "sign", Result: "refused", RefusalCode: &code, CustodyCause: &cause}
			goodCode, goodCause := Code("custody_unavailable"), custodyClosed
			control.RefusalCode, control.CustodyCause = &goodCode, &goodCause
			if c := j.Append(control); c != "" {
				t.Fatal("valid custody control refused", c)
			}
			if err := j.Close(); err != nil {
				t.Fatal(err)
			}
			if kind == "legacy" || kind == "unknown" || kind == "other-refusal" {
				// Rewrite only this isolated fixture with a canonical, self-consistent
				// hash: recovery must reject the enum/linkage, not hash corruption.
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var stored AuditRecord
				if err := json.Unmarshal(bytes.TrimSpace(data), &stored); err != nil {
					t.Fatal(err)
				}
				stored.CustodyCause = r.CustodyCause
				stored.RefusalCode = r.RefusalCode
				stored.Digest, err = auditDigest(stored)
				if err != nil {
					t.Fatal(err)
				}
				data, err = canonical(stored)
				if err != nil {
					t.Fatal(err)
				}
				if kind == "legacy" && bytes.Contains(data, []byte("custody_cause")) {
					t.Fatal("legacy schema changed")
				}
				if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			}
			opened, err := OpenJournal(dir, uint32(os.Getuid()))
			if kind == "unknown" || kind == "other-refusal" || kind == "legacy" {
				if opened != nil || err == nil || !strings.Contains(err.Error(), "invalid audit record") {
					t.Fatal("invalid stored custody cause recovered", err)
				}
			} else {
				if err != nil {
					t.Fatal("valid/historical custody audit did not recover", err)
				}
				opened.Close()
			}
		})
	}
}

// The signing operation itself captures the same bounded causes as public-key
// lookup; healthy custody signs a verifiable signature without cause metadata.
func TestCustodySignCauses(t *testing.T) {
	for _, state := range []string{"closed", "nil", "unloaded", "protection_failed", "open"} {
		t.Run(state, func(t *testing.T) {
			master := &Master{seed: bytes.Repeat([]byte{7}, 32)}
			pub, code := master.Public("m/1'/1'/1'/1'")
			if code != "" {
				t.Fatal(code)
			}
			want := custodyCause(state)
			switch state {
			case "closed":
				master.Close()
			case "nil":
				master = nil
				want = custodyUnloaded
			case "unloaded":
				master.seed = nil
			case "protection_failed":
				master.seed = master.seed[:31]
			}
			data := []byte("fixture signing input")
			sig, code, cause := signForAudit(master, "m/1'/1'/1'/1'", data)
			if state == "open" {
				if code != "" || cause != "" || !ed25519.Verify(pub, data, sig) {
					t.Fatal("open signing control failed")
				}
			} else if sig != nil || code != "custody_unavailable" || cause != want {
				t.Fatal("signing cause mismatch", state, code, cause)
			}
		})
	}
}
