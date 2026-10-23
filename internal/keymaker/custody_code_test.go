package keymaker

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"testing"

	"github.com/relux-works/swarma-keymaker/internal/control"
)

// Closed custody refuses on each real socket with the exact audit code and no
// retained success. Independent open-Master controls still sign/return a key.
func TestCustodyUnavailableVectors(t *testing.T) {
	var doc fixtureDocument
	readFixture(t, "refusals.json", &doc)
	var negative json.RawMessage
	var controlInput json.RawMessage
	for _, row := range doc.Positive {
		if row.ID == "ok-custody-closed" {
			controlInput = row.Input
		}
	}
	for _, row := range doc.Negative {
		if row.ID == "custody-closed" {
			negative = row.Input
			if row.Code != "custody_unavailable" {
				t.Fatal("custody vector code")
			}
		}
	}
	if negative == nil || controlInput == nil {
		t.Fatal("custody vector missing")
	}
	for _, surface := range []string{"agent", "control"} {
		t.Run(surface, func(t *testing.T) {
			for _, input := range []json.RawMessage{negative, controlInput} {
				var facts struct {
					Closed bool `json:"closed"`
				}
				if err := json.Unmarshal(input, &facts); err != nil {
					t.Fatal(err)
				}
				closed := facts.Closed
				name := "control"
				if closed {
					name = "negative"
				}
				t.Run(name, func(t *testing.T) {
					b := nativeOwnBinding()
					f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, &b)
					pub, code := f.master.Public(b.Path)
					if code != "" {
						t.Fatal(code)
					}
					f.start()
					path := f.server.Path
					if surface == "control" {
						path = f.server.ControlPath
					}
					c := nativeDial(t, path)
					if surface == "control" {
						nativeNegotiate(t, c, 1)
					}
					before := nativeSnapshot(t, f)
					if closed {
						f.master.Close()
					}
					if surface == "control" {
						nativeSend(t, c, nativeRequest(2, "pubkey", control.Object{}))
						want := Code("")
						if closed {
							want = "custody_unavailable"
						}
						nativeResponse(t, nativeReceive(t, c), nativeID(2), want)
					} else {
						if err := writeResponse(c, Packet(validBody(pub, "git"))); err != nil {
							t.Fatal(err)
						}
						raw, code := ReadFrame(c)
						if code != "" {
							t.Fatal(code)
						}
						if closed {
							if !bytes.Equal(raw, []byte{5}) {
								t.Fatal("closed custody released signature")
							}
						} else {
							if len(raw) == 0 || raw[0] != 14 {
								t.Fatal("open custody did not sign")
							}
							response := wireReader{b: raw[1:]}
							blob := response.string()
							signed := wireReader{b: blob}
							algorithm := signed.string()
							signature := signed.string()
							request, c := parseAgent(validBody(pub, "git"))
							if c != "" || response.bad || len(response.b) != 0 || signed.bad || len(signed.b) != 0 || string(algorithm) != "ssh-ed25519" || !ed25519.Verify(pub, request.data, signature) {
								t.Fatal("open custody signature did not verify")
							}
						}
					}
					if closed {
						rows := nativeAudit(t, f.store.journal)
						last := rows[len(rows)-1]
						if last.RefusalCode == nil || *last.RefusalCode != "custody_unavailable" {
							t.Fatal("custody refusal misreported", last.RefusalCode)
						}
						if !bytes.Equal(before, nativeSnapshot(t, f)) {
							t.Fatal("custody refusal retained success")
						}
					}
				})
			}
		})
	}
}

// Neither an unloaded nor a nil custody provider may derive a key from an empty
// seed or panic. Both actual surfaces refuse; an open provider remains usable.
func TestMasterUnavailableStates(t *testing.T) {
	for _, state := range []string{"unloaded", "nil"} {
		t.Run(state, func(t *testing.T) {
			for _, surface := range []string{"agent", "control"} {
				t.Run(surface, func(t *testing.T) {
					for _, bad := range []bool{true, false} {
						name := "open-control"
						if bad {
							name = "negative"
						}
						t.Run(name, func(t *testing.T) {
							b := nativeOwnBinding()
							f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, &b)
							public, code := f.master.Public(b.Path)
							if code != "" {
								t.Fatal(code)
							}
							if bad {
								var m *Master
								if state == "unloaded" {
									m = &Master{}
								}
								f.engine.Signer = m
							}
							f.start()
							path := f.server.Path
							if surface == "control" {
								path = f.server.ControlPath
							}
							c := nativeDial(t, path)
							if surface == "control" {
								nativeNegotiate(t, c, 1)
								nativeSend(t, c, nativeRequest(2, "pubkey", control.Object{}))
								want := Code("")
								if bad {
									want = "custody_unavailable"
								}
								nativeResponse(t, nativeReceive(t, c), nativeID(2), want)
							} else {
								writeResponse(c, Packet(validBody(public, "git")))
								raw, code := ReadFrame(c)
								if code != "" {
									t.Fatal(code)
								}
								if bad {
									if !bytes.Equal(raw, []byte{5}) {
										t.Fatal("unloaded custody signed")
									}
								} else if len(raw) == 0 || raw[0] != 14 {
									t.Fatal("open custody refused")
								}
							}
							if bad {
								rows := nativeAudit(t, f.store.journal)
								if rows[len(rows)-1].RefusalCode == nil || *rows[len(rows)-1].RefusalCode != "custody_unavailable" {
									t.Fatal("unloaded custody misreported")
								}
							}
						})
					}
				})
			}
		})
	}
}
