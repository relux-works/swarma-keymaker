package keymaker

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func custodyResultJournal(t *testing.T, uncertain bool) (*Journal, string) {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := OpenDirectory(d, uint32(os.Getuid()), 0700)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dir.Close() })
	var clock AuditClock = systemAuditClock{}
	if uncertain {
		clock = uncertainAuditClock{}
	}
	j, err := openJournal(dir, uint32(os.Getuid()), clock, bytes.NewReader(make([]byte, 16)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.Close() })
	return j, filepath.Join(d, auditName(1))
}

func custodyResultRecord(result, code, cause string) AuditRecord {
	r := AuditRecord{Surface: "agent", Operation: "sign", Result: result}
	if code != "none" {
		c := Code(code)
		r.RefusalCode = &c
	}
	if cause != "none" {
		c := custodyCause(cause)
		r.CustodyCause = &c
	}
	return r
}

func checkCustodyResult(t *testing.T, mode string, r AuditRecord, accept bool) {
	t.Helper()
	j, path := custodyResultJournal(t, false)
	valid := custodyResultRecord("refused", "custody_unavailable", "closed")
	if mode != "Recovery" {
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		seq, previous, size, total, failed := j.seq, j.previous, j.size, j.total, j.failed
		var code Code
		if mode == "Append" {
			code = j.Append(r)
		} else {
			code = j.AppendContext(context.Background(), r)
		}
		if accept {
			if code != "" || j.seq != seq+1 {
				t.Fatal("valid custody linkage refused", code)
			}
		} else {
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if code != "audit_unavailable" || !bytes.Equal(before, after) || j.seq != seq || j.previous != previous || j.size != size || j.total != total || j.failed != failed {
				t.Fatal("invalid custody result admitted or changed journal", code)
			}
		}
		if code := j.Append(valid); code != "" {
			t.Fatal("valid refusal control failed", code)
		}
		return
	}
	if c := j.Append(valid); c != "" {
		t.Fatal(c)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var stored AuditRecord
	if err := json.Unmarshal(bytes.TrimSpace(original), &stored); err != nil {
		t.Fatal(err)
	}
	stored.Result, stored.RefusalCode, stored.CustodyCause = r.Result, r.RefusalCode, r.CustodyCause
	stored.Digest, err = auditDigest(stored)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := canonical(stored)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	opened, err := OpenJournal(j.dir, uint32(os.Getuid()))
	if opened != nil {
		opened.Close()
	}
	if accept {
		if err != nil {
			t.Fatal("valid custody recovery refused", err)
		}
	} else if opened != nil || err == nil || !strings.Contains(err.Error(), "invalid audit record") {
		t.Fatal("invalid custody result recovered", err)
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(after, raw) {
		t.Fatal("recovery rewrote audit evidence", readErr)
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	control, err := OpenJournal(j.dir, uint32(os.Getuid()))
	if err != nil {
		t.Fatal("valid refusal recovery control failed", err)
	}
	control.Close()
}

// A correctly hashed success/unknown/other result cannot carry custody metadata.
// Both append APIs reject before writes; recovery rejects the rehashed record.
// Each negative is paired with a real refused/cause control through the same API.
func TestCustodyResultLinkage(t *testing.T) {
	for _, mode := range []string{"Append", "AppendContext", "Recovery"} {
		t.Run(mode, func(t *testing.T) {
			for _, result := range []string{"success", "unknown", "other", "", "refused"} {
				name := result
				if name == "" {
					name = "empty"
				}
				t.Run(name, func(t *testing.T) {
					checkCustodyResult(t, mode, custodyResultRecord(result, "custody_unavailable", "closed"), result == "refused")
				})
			}
		})
	}
}

// This literal table covers every combination of the three specified Results,
// code class (absent/custody/other), and absent/three valid/invalid causes. It
// checks custody linkage, not unrelated generic audit-schema constraints.
// Append and recovery expectations are separate: absent historical metadata is
// accepted only by recovery, while all present metadata retains strict linkage.
func TestCustodyResultMatrix(t *testing.T) {
	causes := []string{"none", "closed", "unloaded", "protection_failed", "invalid"}
	rows := []struct {
		result, code     string
		append, recovery [5]bool
	}{
		{"refused", "none", [5]bool{true, false, false, false, false}, [5]bool{true, false, false, false, false}},
		{"refused", "custody_unavailable", [5]bool{false, true, true, true, false}, [5]bool{true, true, true, true, false}},
		{"refused", "binding_not_found", [5]bool{true, false, false, false, false}, [5]bool{true, false, false, false, false}},
		{"success", "none", [5]bool{true, false, false, false, false}, [5]bool{true, false, false, false, false}},
		{"success", "custody_unavailable", [5]bool{false, false, false, false, false}, [5]bool{true, false, false, false, false}},
		{"success", "binding_not_found", [5]bool{true, false, false, false, false}, [5]bool{true, false, false, false, false}},
		{"unknown", "none", [5]bool{true, false, false, false, false}, [5]bool{true, false, false, false, false}},
		{"unknown", "custody_unavailable", [5]bool{false, false, false, false, false}, [5]bool{true, false, false, false, false}},
		{"unknown", "binding_not_found", [5]bool{true, false, false, false, false}, [5]bool{true, false, false, false, false}},
	}
	for _, mode := range []string{"Append", "AppendContext", "Recovery"} {
		t.Run(mode, func(t *testing.T) {
			for _, row := range rows {
				for i, cause := range causes {
					t.Run(row.result+"/"+row.code+"/"+cause, func(t *testing.T) {
						accept := row.append[i]
						if mode == "Recovery" {
							accept = row.recovery[i]
						}
						checkCustodyResult(t, mode, custodyResultRecord(row.result, row.code, cause), accept)
					})
				}
			}
		})
	}
}

// Untrusted time rewrites Result to unknown. Custody metadata must therefore
// fail before durable bytes on both APIs; ordinary unknown audit still works.
func TestCustodyResultClock(t *testing.T) {
	for _, mode := range []string{"Append", "AppendContext"} {
		t.Run(mode, func(t *testing.T) {
			j, path := custodyResultJournal(t, true)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			r := custodyResultRecord("refused", "custody_unavailable", "closed")
			var code Code
			if mode == "Append" {
				code = j.Append(r)
			} else {
				code = j.AppendContext(context.Background(), r)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if code != "audit_unavailable" || !bytes.Equal(before, after) || j.seq != 0 || j.failed {
				t.Fatal("unknown-time custody record appended", code)
			}
			if code := j.Append(AuditRecord{Surface: "agent", Operation: "pubkey", Result: "success"}); code != "" {
				t.Fatal("ordinary unknown-time control refused", code)
			}
			rows := nativeAudit(t, j)
			last := rows[len(rows)-1]
			if last.Result != "unknown" || last.Time != nil || last.CustodyCause != nil {
				t.Fatal("unknown-time semantics changed")
			}
		})
	}
}
