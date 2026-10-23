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
		bytes.Replace(raw, []byte(`"operator_principal"`), []byte(`"Operator_Principal"`), 1),
		bytes.Replace(raw, []byte(`"generation"`), []byte(`"Generation"`), 1),
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

// The example's optional helper uses main's exact nested schema through the
// single serve/offline decoder. Omission disables it; malformed authority
// objects refuse before any file access. Registry resolution/readiness is not
// established by this byte-only configuration test.
func TestPackagingRegistrationHelper(t *testing.T) {
	raw, err := os.ReadFile("../../packaging/config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"omitted", "null", "wrong-type", "missing-names", "missing-enrollment", "missing-approval", "missing-purpose", "unknown-helper", "unknown-name", "wrong-name-type"} {
		t.Run(kind, func(t *testing.T) {
			var fields map[string]any
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			helper, ok := fields["registration_helper"].(map[string]any)
			if !ok {
				t.Fatal("example missing helper schema")
			}
			names := helper["names"].(map[string]any)
			switch kind {
			case "omitted":
				delete(fields, "registration_helper")
			case "null":
				fields["registration_helper"] = nil
			case "wrong-type":
				fields["registration_helper"] = true
			case "missing-names":
				delete(helper, "names")
			case "missing-enrollment":
				delete(helper, "enrollment_config")
			case "missing-approval":
				delete(helper, "approval_file")
			case "missing-purpose":
				delete(names, "purpose")
			case "unknown-helper":
				helper["caller_key"] = "forbidden"
			case "unknown-name":
				names["path"] = "forbidden"
			case "wrong-name-type":
				names["agent"] = false
			}
			changed, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			cfg, offline := ParseConfig(bytes.NewReader(changed))
			var served productionConfig
			online := StrictJSON(bytes.NewReader(changed), &served)
			if kind == "omitted" {
				if offline != nil || online != nil || cfg.Registration != nil || served.Registration != nil {
					t.Fatal("helper omission control refused", offline, online)
				}
			} else if offline == nil || online == nil {
				t.Fatal("malformed optional helper admitted", kind, offline, online)
			}
			cfg, err = ParseConfig(bytes.NewReader(raw))
			if err != nil {
				t.Fatal("helper example control refused", err)
			}
			if err := StrictJSON(bytes.NewReader(raw), &served); err != nil {
				t.Fatal("served helper example refused", err)
			}
			if cfg.Registration == nil || served.Registration == nil || cfg.Registration.Names.Purpose != "host-registration" || cfg.Registration.EnrollmentConfig == "" || cfg.Registration.ApprovalFile == "" {
				t.Fatal("helper example lost required members")
			}
		})
	}
}
