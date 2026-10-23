package keymaker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keymaker/internal/control"
	format "github.com/relux-works/swarma-registrar/registration"
)

func helperResult(t *testing.T, obj control.Object, id string, want Code, key string) []byte {
	t.Helper()
	if want != "" {
		nativeResponse(t, obj, id, want)
		return nil
	}
	if len(obj) != 2 || obj["request_id"] != id {
		t.Fatal("helper wrapper", obj)
	}
	result, ok := obj["result"].(control.Object)
	if !ok {
		t.Fatal("helper refused positive control", obj)
	}
	raw, c := helperEnvelope(result)
	if c != "" {
		t.Fatal(c)
	}
	body, err := format.Verify(raw)
	if err != nil || body.Key != key {
		t.Fatal("helper did not verify under enrolled purpose-2 key", err)
	}
	if body.Name == "" || body.Audience != helperAudience {
		t.Fatal("helper body authority")
	}
	return raw
}

// Each authored helper row runs negative first and its exact paired control
// through the real daemon socket, Linux peer credentials, Master and signed Git
// enrollment loader. Numeric UID roles are projected onto this process's UID;
// real foreign UIDs remain a separate reviewer-run window qualification.
func TestDaemonHelperVectors(t *testing.T) {
	var doc fixtureDocument
	readFixture(t, "refusals.json", &doc)
	positives := map[string]json.RawMessage{}
	for _, r := range doc.Positive {
		positives[r.ID] = r.Input
	}
	count := 0
	for _, row := range doc.Negative {
		if !strings.HasPrefix(row.ID, "helper-") {
			continue
		}
		count++
		t.Run(row.ID, func(t *testing.T) {
			for _, sample := range []struct {
				name string
				raw  json.RawMessage
				want Code
			}{{"negative", row.Input, row.Code}, {"control", positives[row.Control], ""}} {
				t.Run(sample.name, func(t *testing.T) { runDaemonHelperVector(t, sample.raw, sample.want) })
			}
		})
	}
	if count != 16 {
		t.Fatal("helper coverage drift", count)
	}
}
func runDaemonHelperVector(t *testing.T, raw json.RawMessage, want Code) {
	t.Helper()
	var input struct {
		PeerUID    uint32 `json:"peer_uid"`
		Generation string `json:"generation"`
		Admitted   string `json:"admitted_generation"`
		Binding    string `json:"binding_status"`
		Enrollment struct {
			Available   bool             `json:"available"`
			Verified    bool             `json:"verified"`
			State       string           `json:"state"`
			UIDMap      []map[string]any `json:"uid_map"`
			Names       map[string]any   `json:"names"`
			KeyEnrolled bool             `json:"key_enrolled"`
		} `json:"enrollment"`
		Request json.RawMessage `json:"request"`
	}
	if err := json.Unmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}
	b := nativeOwnBinding()
	b.Generation = input.Generation
	var binding *Binding
	if input.Binding != "absent" {
		binding = &b
	}
	f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, binding)
	f.generation.entries[b.UID] = Generation{UID: b.UID, Generation: b.Generation, State: "active", Verified: true, Revision: "fixture-order", Provenance: "verified-fixture"}
	if input.Binding == "revoked" {
		if c := f.store.Revoke(context.Background(), f.config.Operator, f.config.Operator, 1, approvedAct{}); c != "" {
			t.Fatal(c)
		}
	}
	body := helperBody(t, f, b.UID)
	body["state"] = input.Enrollment.State
	body["names"] = input.Enrollment.Names
	if input.Enrollment.UIDMap == nil {
		delete(body, "uid_map")
	} else {
		rows := []any{}
		for _, row := range input.Enrollment.UIDMap {
			rowUID := uint32(row["uid"].(float64))
			mapped := b.UID
			if rowUID != input.PeerUID {
				mapped++
			}
			row["uid"] = int64(mapped)
			rows = append(rows, row)
		}
		body["uid_map"] = rows
	}
	if !input.Enrollment.KeyEnrolled {
		other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{19}, 32))
		body["keys"].([]any)[0].(map[string]any)["key"] = "ed25519:" + base64.RawURLEncoding.EncodeToString(other[32:])
	}
	verified := input.Enrollment.Verified && input.Enrollment.UIDMap != nil
	trust := newHelperTrust(t, f, body, map[string]string{strconv.FormatUint(uint64(b.UID), 10): input.Admitted}, verified)
	if !input.Enrollment.Available {
		if e := os.Remove(trust.config); e != nil {
			t.Fatal(e)
		}
		if c := trust.authority.Reload(context.Background()); c != "enrollment_unavailable" {
			t.Fatal(c)
		}
	}
	f.native.Config.Helper = trust.helper
	f.config.Helper = trust.helper
	f.start()
	conn := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, conn, 100)
	before := nativeSnapshot(t, f)
	canonical, e := canonical(input.Request)
	if e != nil {
		t.Fatal(e)
	}
	request, e := control.Decode(canonical)
	if e != nil {
		t.Fatal(e)
	}
	nativeSend(t, conn, request)
	helperResult(t, nativeReceive(t, conn), request["request_id"].(string), want, trust.helper.key)
	if want != "" && !bytes.Equal(before, nativeSnapshot(t, f)) {
		t.Fatal("helper refusal mutated durable results")
	}
	records := nativeAudit(t, f.store.journal)
	last := records[len(records)-1]
	if last.Domain == nil || *last.Domain != "registration/1" {
		t.Fatal("helper logical domain missing")
	}
	if want != "" && (last.RefusalCode == nil || *last.RefusalCode != want) {
		t.Fatal("helper refusal audit mismatch")
	}
	if want != "" {
		// Enrollment or binding refusal leaves transport admission alive for hello.
		next := nativeDial(t, f.server.ControlPath)
		nativeNegotiate(t, next, 101)
	}
}
