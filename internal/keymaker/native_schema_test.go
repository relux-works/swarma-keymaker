package keymaker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/relux-works/swarma-keymaker/internal/control"
)

// The retained-request decoder independently rejects incomplete or ambiguous
// authority/result rows. Reconciliation is deliberately bypassed for negatives;
// the unchanged positive reopens the real paired Store with its original ID.
func TestNativeRetainedSchema(t *testing.T) {
	f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, nil)
	f.start()
	c := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, c, 1)
	f.stop(t)
	f.store.Close()
	original := nativeSnapshot(t, f)
	path := fmt.Sprintf("/proc/self/fd/%d/bindings.json", f.state.Fd())
	cases := []string{"unknown-row", "unknown-caller", "bad-arguments", "bad-id", "bad-method", "bad-status", "null-result", "duplicate"}
	for _, field := range []string{"caller", "id", "method", "arguments", "status", "result", "caller.uid", "caller.generation"} {
		cases = append(cases, "missing-"+field, "null-"+field)
	}
	for _, mode := range cases {
		t.Run(mode, func(t *testing.T) {
			var disk map[string]any
			if err := json.Unmarshal(original, &disk); err != nil {
				t.Fatal(err)
			}
			rows := disk["requests"].([]any)
			row := rows[0].(map[string]any)
			switch mode {
			case "unknown-row":
				row["extra"] = true
			case "unknown-caller":
				row["caller"].(map[string]any)["extra"] = true
			case "bad-arguments":
				row["arguments"] = "{ }"
			case "bad-id":
				row["id"] = "ABC"
			case "bad-method":
				row["method"] = "sign"
			case "bad-status":
				row["status"] = "success"
			case "null-result":
				row["result"] = nil
			case "duplicate":
				disk["requests"] = append(rows, row)
			default:
				field, target := "", row
				isNull := mode[:5] == "null-"
				if isNull {
					field = mode[5:]
				} else {
					field = mode[8:]
				}
				if len(field) > 7 && field[:7] == "caller." {
					target = row["caller"].(map[string]any)
					field = field[7:]
				}
				if isNull {
					target[field] = nil
				} else {
					delete(target, field)
				}
			}
			data, err := json.Marshal(disk)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if got, err := loadStore(f.state, uint32(os.Getuid())); err == nil || got != nil {
				t.Fatal("invalid retained row admitted", mode)
			}
			if got := nativeSnapshot(t, f); !bytes.Equal(got, data) {
				t.Fatal("decoder rewrote rejected evidence")
			}
		})
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	recovered, err := OpenStore(f.state, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if len(recovered.requests) != 1 || recovered.requests[0].ID != nativeID(1) {
		t.Fatal("intact retained ID lost")
	}
}

// Omitted numeric authority must not silently default to UID/GID zero. This
// tests strict config decoding, not root ownership/provisioning of its file.
func TestNativeConfigSchema(t *testing.T) {
	original := map[string]any{"socket_dir": "/run/example", "state_dir": "/var/lib/example", "master_file": "/var/lib/example-seed/master", "registry_file": "/etc/example-registry.json", "service_uid": uint32(30000), "service_gid": uint32(30000), "control_gid": uint32(30002), "operator_principal": map[string]any{"uid": uint32(30003), "generation": nativeToken}, "master_epoch": "fixture", "registry_revision": "fixture"}
	data, _ := json.Marshal(original)
	for _, mode := range []string{"missing-operator", "missing-group", "missing-uid", "null-uid", "missing-generation", "unknown-principal", "intact"} {
		t.Run(mode, func(t *testing.T) {
			var obj map[string]any
			json.Unmarshal(data, &obj)
			principal := obj["operator_principal"].(map[string]any)
			switch mode {
			case "missing-operator":
				delete(obj, "operator_principal")
			case "missing-group":
				delete(obj, "control_gid")
			case "missing-uid":
				delete(principal, "uid")
			case "null-uid":
				principal["uid"] = nil
			case "missing-generation":
				delete(principal, "generation")
			case "unknown-principal":
				principal["role"] = "operator"
			}
			raw, _ := json.Marshal(obj)
			var cfg productionConfig
			err := StrictJSON(bytes.NewReader(raw), &cfg)
			if mode != "intact" {
				if err == nil {
					t.Fatal("incomplete config authority admitted")
				}
				return
			}
			if err != nil || cfg.ControlGID != 30002 || cfg.Operator != (Principal{30003, nativeToken}) {
				t.Fatal("intact config refused", err)
			}
		})
	}
}

// Same kernel UID with a different configured operator generation has no
// mutation authority. The configured tuple admits the matching registration.
func TestNativeOperatorGeneration(t *testing.T) {
	for _, configured := range []string{"different-generation", nativeToken} {
		t.Run(configured, func(t *testing.T) {
			f := nativeBase(t, Principal{uint32(os.Getuid()), configured}, nil, nil)
			nativeTarget(f)
			f.start()
			c := nativeDial(t, f.server.ControlPath)
			nativeNegotiate(t, c, 1)
			before := nativeSnapshot(t, f)
			nativeSend(t, c, nativeRegisterRequest(2))
			want := Code("")
			if configured != nativeToken {
				want = "role_not_permitted"
			}
			nativeResponse(t, nativeReceive(t, c), nativeID(2), want)
			if want != "" && !bytes.Equal(before, nativeSnapshot(t, f)) {
				t.Fatal("wrong operator generation mutated state")
			}
		})
	}
}

// pubkey cannot select another identity. Each refusal leaves durable state
// unchanged, then a fresh own-key request succeeds on that same connection.
func TestNativePubkeySelectors(t *testing.T) {
	for _, field := range []string{"uid", "generation", "identity", "path"} {
		t.Run(field, func(t *testing.T) {
			b := nativeOwnBinding()
			f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, &b)
			f.start()
			c := nativeDial(t, f.server.ControlPath)
			nativeNegotiate(t, c, 1)
			before := nativeSnapshot(t, f)
			nativeSend(t, c, nativeRequest(2, "pubkey", control.Object{field: "other"}))
			nativeResponse(t, nativeReceive(t, c), nativeID(2), "request_malformed")
			if !bytes.Equal(before, nativeSnapshot(t, f)) {
				t.Fatal("selector refusal changed state")
			}
			nativeSend(t, c, nativeRequest(3, "pubkey", control.Object{}))
			result := nativeResponse(t, nativeReceive(t, c), nativeID(3), "")
			if result["path"] != b.Path {
				t.Fatal("own-key control selected another identity")
			}
		})
	}
}

// Target evidence and the exact register schema are checked before a durable
// intent or binding effect. Restoring the target/schema admits a real register.
func TestNativeRegisterGuards(t *testing.T) {
	for _, mode := range []string{"unknown-param", "missing-name", "wrong-purpose", "uid-overflow", "target-inactive", "target-mismatch", "target-unavailable", "target-bound"} {
		t.Run(mode, func(t *testing.T) {
			f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, nil)
			nativeTarget(f)
			request := nativeRegisterRequest(2)
			params := request["params"].(control.Object)
			want := Code("request_malformed")
			switch mode {
			case "unknown-param":
				params["uid"] = int64(1)
			case "missing-name":
				delete(params["names"].(control.Object), "product")
			case "wrong-purpose":
				params["names"].(control.Object)["purpose"] = "other"
				want = "purpose_unknown"
			case "uid-overflow":
				params["target_uid"] = int64(4294967296)
			case "target-inactive":
				f.generation.set(30001, "retiring", nativeToken)
				want = "generation_inactive"
			case "target-mismatch":
				f.generation.set(30001, "active", "replacement")
				want = "generation_mismatch"
			case "target-unavailable":
				delete(f.generation.entries, 30001)
				want = "generation_source_unavailable"
			case "target-bound":
				b := fixtureBinding(30001)
				b.Generation = nativeToken
				if _, code := f.store.Register(f.config.Operator, f.config.Operator, b); code != "" {
					t.Fatal(code)
				}
				want = "binding_conflict"
			}
			f.start()
			c := nativeDial(t, f.server.ControlPath)
			nativeNegotiate(t, c, 1)
			before := nativeSnapshot(t, f)
			nativeSend(t, c, request)
			nativeResponse(t, nativeReceive(t, c), nativeID(2), want)
			if !bytes.Equal(before, nativeSnapshot(t, f)) {
				t.Fatal("invalid target/schema changed binding or retained IDs")
			}
			f.generation.mu.Lock()
			f.generation.entries[30002] = Generation{UID: 30002, Generation: nativeToken, State: "active", Revision: "fixture-order", Provenance: "verified-fixture", Verified: true}
			f.generation.mu.Unlock()
			fresh := nativeDial(t, f.server.ControlPath)
			nativeNegotiate(t, fresh, 3)
			valid := nativeRegisterRequest(4)
			valid["params"].(control.Object)["target_uid"] = int64(30002)
			valid["params"].(control.Object)["names"].(control.Object)["agent"] = "station-b"
			nativeSend(t, fresh, valid)
			nativeResponse(t, nativeReceive(t, fresh), nativeID(4), "")
		})
	}
}
