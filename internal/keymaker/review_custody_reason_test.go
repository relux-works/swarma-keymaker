package keymaker

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/relux-works/swarma-keymaker/internal/control"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A success must never carry custody_cause, even if a contradictory refusal_code
// is supplied. Check the public journal append/recovery paths and valid controls.
func TestReviewCustodySuccessMetadata(t *testing.T) {
	for _, mode := range []string{"append-control", "append-success", "recover-control", "recover-success"} {
		t.Run(mode, func(t *testing.T) {
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
			code, cause := Code("custody_unavailable"), custodyClosed
			r := AuditRecord{Surface: "agent", Operation: "sign", Result: "refused", RefusalCode: &code, CustodyCause: &cause}
			path := filepath.Join(d, auditName(1))
			if mode == "append-success" {
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				r.Result = "success"
				got := j.Append(r)
				after, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				seq := j.seq
				j.Close()
				if got != "audit_unavailable" || !bytes.Equal(before, after) || seq != 0 {
					t.Fatalf("success admitted custody cause: code=%q appended=%t seq=%d", got, !bytes.Equal(before, after), seq)
				}
				return
			}
			if got := j.Append(r); got != "" {
				t.Fatal("valid custody control refused", got)
			}
			if mode == "append-control" {
				if got := j.Append(AuditRecord{Surface: "agent", Operation: "pubkey", Result: "success"}); got != "" {
					t.Fatal("clean success control refused", got)
				}
			}
			if err := j.Close(); err != nil {
				t.Fatal(err)
			}
			if mode == "recover-success" {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var stored AuditRecord
				if err := json.Unmarshal(bytes.TrimSpace(data), &stored); err != nil {
					t.Fatal(err)
				}
				stored.Result = "success"
				stored.Digest, err = auditDigest(stored)
				if err != nil {
					t.Fatal(err)
				}
				data, err = canonical(stored)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			}
			opened, err := OpenJournal(dir, uint32(os.Getuid()))
			if opened != nil {
				opened.Close()
			}
			if mode == "recover-success" {
				if err == nil || !strings.Contains(err.Error(), "invalid audit record") {
					t.Fatalf("recovery admitted custody cause on success: %v", err)
				}
			} else if err != nil {
				t.Fatal("valid recovery control refused", err)
			}
		})
	}
}

// A real admitted request resets prior connection-local metadata. Other refusal
// codes and a healthy operation must omit it; no concurrent mutation is used.
func TestReviewCustodyRequestReset(t *testing.T) {
	b := nativeOwnBinding()
	f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, &b)
	connection := &nativeConnection{custodyCause: custodyClosed}
	ctx := context.WithValue(context.Background(), nativeConnectionKey{}, connection)
	peer := control.Peer{UID: uint32(os.Getuid()), Generation: nativeToken}
	r := control.Request{ID: nativeID(2), Method: "pubkey", Params: control.Object{}}
	if c := f.native.Admit(ctx, peer, r); c != "" {
		t.Fatal("admission control refused", c)
	}
	if connection.custodyCause != "" {
		t.Fatal("admitted request retained stale custody cause")
	}
	connection.custodyCause = custodyClosed
	if c := f.native.Refuse(ctx, nil, &peer, r, nil, "request_malformed"); c != "request_malformed" {
		t.Fatal("other refusal changed", c)
	}
	rows := nativeAudit(t, f.store.journal)
	if rows[len(rows)-1].CustodyCause != nil {
		t.Fatal("other code carried stale cause")
	}
}
