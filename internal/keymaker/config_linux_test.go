//go:build linux

package keymaker

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

// The shipped example uses the actual serve Config decoder, with numeric zero
// placeholders awaiting allocation. Every missing/unknown/null/wrong-type
// member refuses; the untouched example remains a nearby parsing control.
// This does not qualify file ownership, UID provisioning or daemon readiness.
func TestPackagingConfigExample(t *testing.T) {
	raw, err := os.ReadFile("../../packaging/config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var original map[string]json.RawMessage
	if err := json.Unmarshal(raw, &original); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"socket_dir", "state_dir", "master_file", "registry_file", "service_uid", "service_gid", "control_gid", "operator_principal", "master_epoch", "registry_revision"} {
		for _, mode := range []string{"missing", "null", "wrong-type"} {
			t.Run(mode+"-"+key, func(t *testing.T) {
				obj := map[string]json.RawMessage{}
				for k, v := range original {
					obj[k] = v
				}
				switch mode {
				case "missing":
					delete(obj, key)
				case "null":
					obj[key] = json.RawMessage("null")
				case "wrong-type":
					obj[key] = json.RawMessage("true")
				}
				changed, _ := json.Marshal(obj)
				if _, err := ParseConfig(bytes.NewReader(changed)); err == nil {
					t.Fatal("invalid service config admitted")
				}
				if _, err := ParseConfig(bytes.NewReader(raw)); err != nil {
					t.Fatal("valid example control refused", err)
				}
			})
		}
	}
	t.Run("unknown", func(t *testing.T) {
		original["unknown"] = json.RawMessage("true")
		changed, _ := json.Marshal(original)
		if _, err := ParseConfig(bytes.NewReader(changed)); err == nil {
			t.Fatal("unknown service config member admitted")
		}
		cfg, err := ParseConfig(bytes.NewReader(raw))
		if err != nil || cfg.ServiceUID != 0 || cfg.ServiceGID != 0 || cfg.ControlGID != 0 {
			t.Fatal("example placeholder control refused", err)
		}
	})
}

// The production typed decoder and offline entry point share rejection of
// ambiguous JSON, relative paths, empty pins and numeric overflow. These checks
// parse bytes only; they do not access the example's installation paths.
func TestPackagingConfigSemantics(t *testing.T) {
	raw, err := os.ReadFile("../../packaging/config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{
		append(append([]byte(nil), raw...), []byte("{}")...),
		bytes.Replace(raw, []byte(`"service_uid": 0`), []byte(`"service_uid": 0, "service_uid": 1`), 1),
		bytes.Replace(raw, []byte(`"service_uid": 0`), []byte(`"service_uid": 4294967296`), 1),
		bytes.Replace(raw, []byte(`"service_uid": 0`), []byte(`"service_uid": -1`), 1),
		bytes.Replace(raw, []byte(`"/run/swarma-keymaker"`), []byte(`"relative"`), 1),
		bytes.Replace(raw, []byte(`"REPLACE_WITH_PINNED_MASTER_EPOCH"`), []byte(`""`), 1),
	} {
		var served productionConfig
		if _, err := ParseConfig(bytes.NewReader(bad)); err == nil {
			t.Fatal("invalid offline config accepted")
		}
		if err := StrictJSON(bytes.NewReader(bad), &served); err == nil {
			t.Fatal("invalid serve config accepted")
		}
		if _, err := ParseConfig(bytes.NewReader(raw)); err != nil {
			t.Fatal("valid offline control refused", err)
		}
		if err := StrictJSON(bytes.NewReader(raw), &served); err != nil {
			t.Fatal("valid serve control refused", err)
		}
	}
}
