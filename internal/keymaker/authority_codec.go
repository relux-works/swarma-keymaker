package keymaker

// PC2 S1 is a pure codec. No Store, daemon, installer, floor writer, filesystem
// authority, admission decision or lock calls this code. G4 is its byte contract.
import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/relux-works/swarma-keymaker/internal/control"
	"github.com/relux-works/waggle/record"
)

type authorityKind string

const (
	// These explicit preimage selectors are internal, never serialized domain tags.
	authorityRootKind            authorityKind = "keymaker-authority/2"
	authorityRootPreimageKind    authorityKind = "keymaker-authority-root-preimage/2"
	authorityBodyFieldsKind      authorityKind = "keymaker-authority-body-fields/2"
	authoritySnapshotKind        authorityKind = "keymaker-combined-snapshot/3"
	authorityAttemptPreimageKind authorityKind = "pc2-activation-attempt-preimage/1"
	authorityRootLimit                         = 1048576
	authoritySafeInteger         int64         = 9007199254740991
)

type authorityCodecError struct{ Code string }

func (e *authorityCodecError) Error() string { return "PC2 codec: " + e.Code }
func authorityFail(code string) error        { return &authorityCodecError{code} }
func authorityCode(e error) string {
	var v *authorityCodecError
	if errors.As(e, &v) {
		return v.Code
	}
	return ""
}
func authorityLimit(k authorityKind) int {
	switch k {
	case authorityRootKind, authorityRootPreimageKind, authorityBodyFieldsKind, "keymaker-authority-facts/1":
		return authorityRootLimit
	case "pc2-activation-attempt/1", authorityAttemptPreimageKind, "pc2-hold/1", "keymaker-provenance/1":
		return 4096
	case "keymaker-authority-floor/1", "keymaker-authority-intent/1", "keymaker-authority-link/1", "pc2-recovery-record/1":
		return 8192
	case "keymaker-participants/1", "keymaker-reservation/1", "pc2-manager-inventory/1", "pc2-recovery-guard/1", "keymaker-capacity-genesis/1", "keymaker-message-policy/1", "message-freshness/1":
		return 65536
	default:
		return stateBudget
	}
}

// Parse raw tokens before allocation of nested containers. encoding/json never
// decides acceptance: duplicate decoded names, lexical integers, depth, UTF-8
// and exact canonical re-encoding are independently required. Surrogate repair,
// escaped aliases and whitespace cannot round-trip and are refused.
func parseAuthorityCCJ(raw []byte, limit int) (map[string]any, error) {
	if limit <= 0 || len(raw) > limit {
		return nil, authorityFail("total_limit")
	}
	if !utf8.Valid(raw) {
		return nil, authorityFail("invalid_utf8")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) (any, error)
	value = func(depth int) (any, error) {
		tok, e := d.Token()
		if e != nil {
			return nil, authorityFail("truncated")
		}
		switch x := tok.(type) {
		case json.Delim:
			if depth >= 16 {
				return nil, authorityFail("depth_limit")
			}
			switch x {
			case '{':
				o := map[string]any{}
				for d.More() {
					key, e := d.Token()
					if e != nil {
						return nil, authorityFail("truncated")
					}
					k, ok := key.(string)
					if !ok {
						return nil, authorityFail("wrong_type")
					}
					if _, ok = o[k]; ok {
						return nil, authorityFail("duplicate_member")
					}
					v, e := value(depth + 1)
					if e != nil {
						return nil, e
					}
					o[k] = v
				}
				end, e := d.Token()
				if e != nil || end != json.Delim('}') {
					return nil, authorityFail("truncated")
				}
				return o, nil
			case '[':
				a := []any{}
				for d.More() {
					v, e := value(depth + 1)
					if e != nil {
						return nil, e
					}
					a = append(a, v)
				}
				end, e := d.Token()
				if e != nil || end != json.Delim(']') {
					return nil, authorityFail("truncated")
				}
				return a, nil
			}
		case json.Number:
			s := string(x)
			if s == "-0" {
				return nil, authorityFail("negative_zero")
			}
			if strings.ContainsAny(s, "eE") {
				return nil, authorityFail("exponent")
			}
			if strings.Contains(s, ".") {
				return nil, authorityFail("fraction")
			}
			n, e := strconv.ParseInt(s, 10, 64)
			if e != nil || n > authoritySafeInteger || n < -authoritySafeInteger {
				return nil, authorityFail("integer_overflow")
			}
			return n, nil
		case string, bool, nil:
			return tok, nil
		}
		return nil, authorityFail("wrong_type")
	}
	v, e := value(0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, authorityFail("extra_document")
	}
	o, ok := v.(map[string]any)
	if !ok {
		return nil, authorityFail("wrong_type")
	}
	b, e := marshalAuthorityCCJ(o, limit)
	if e != nil {
		return nil, e
	}
	if !bytes.Equal(b, raw) {
		return nil, authorityFail("noncanonical")
	}
	return o, nil
}

// Encode only explicit CCJ tree values. The size budget is checked on every
// append (including escaped strings), before output growth; typed formats impose
// their smaller per-object cap separately. Maps/arrays are never silently null.
func marshalAuthorityCCJ(o map[string]any, limit int) ([]byte, error) {
	var out []byte
	add := func(s string) error {
		if len(s) > limit-len(out) {
			return authorityFail("total_limit")
		}
		out = append(out, s...)
		return nil
	}
	quote := func(s string) error {
		if !utf8.ValidString(s) {
			return authorityFail("invalid_utf8")
		}
		if e := add("\""); e != nil {
			return e
		}
		for _, r := range s {
			var part string
			switch r {
			case '"':
				part = `\"`
			case '\\':
				part = `\\`
			case '\b':
				part = `\b`
			case '\f':
				part = `\f`
			case '\n':
				part = `\n`
			case '\r':
				part = `\r`
			case '\t':
				part = `\t`
			default:
				if r < 32 {
					part = fmt.Sprintf(`\u%04x`, r)
				} else {
					part = string(r)
				}
			}
			if e := add(part); e != nil {
				return e
			}
		}
		return add("\"")
	}
	var emit func(any, int) error
	emit = func(v any, depth int) error {
		switch x := v.(type) {
		case nil:
			return add("null")
		case bool:
			return add(strconv.FormatBool(x))
		case int64:
			if x > authoritySafeInteger || x < -authoritySafeInteger {
				return authorityFail("integer_overflow")
			}
			return add(strconv.FormatInt(x, 10))
		case string:
			return quote(x)
		case map[string]any:
			if depth >= 16 {
				return authorityFail("depth_limit")
			}
			if x == nil {
				return authorityFail("null_member")
			}
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			if e := add("{"); e != nil {
				return e
			}
			for i, k := range keys {
				if i > 0 {
					if e := add(","); e != nil {
						return e
					}
				}
				if e := quote(k); e != nil {
					return e
				}
				if e := add(":"); e != nil {
					return e
				}
				if e := emit(x[k], depth+1); e != nil {
					return e
				}
			}
			return add("}")
		case []any:
			if depth >= 16 {
				return authorityFail("depth_limit")
			}
			if x == nil {
				return authorityFail("null_member")
			}
			if e := add("["); e != nil {
				return e
			}
			for i, v := range x {
				if i > 0 {
					if e := add(","); e != nil {
						return e
					}
				}
				if e := emit(v, depth+1); e != nil {
					return e
				}
			}
			return add("]")
		default:
			return authorityFail("wrong_type")
		}
	}
	if e := emit(o, 0); e != nil {
		return nil, e
	}
	return out, nil
}

type authorityRule func(any) error

func arObject(fields map[string]authorityRule) authorityRule {
	return func(v any) error {
		o, ok := v.(map[string]any)
		if !ok {
			return authorityFail("wrong_type")
		}
		for k := range o {
			if _, ok := fields[k]; !ok {
				for want := range fields {
					if strings.EqualFold(strings.ReplaceAll(k, "_", ""), strings.ReplaceAll(want, "_", "")) {
						return authorityFail("alias_member")
					}
				}
				return authorityFail("unknown_member")
			}
		}
		keys := make([]string, 0, len(fields))
		for k := range fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v, ok := o[k]
			if !ok {
				return authorityFail("missing_member")
			}
			if e := fields[k](v); e != nil {
				return fmt.Errorf("%s: %w", k, e)
			}
		}
		return nil
	}
}
func arNullable(r authorityRule) authorityRule {
	return func(v any) error {
		if v == nil {
			return nil
		}
		return r(v)
	}
}
func arInt(lo, hi int64) authorityRule {
	return func(v any) error {
		n, ok := v.(int64)
		if !ok {
			return authorityFail("wrong_type")
		}
		if n < lo || n > hi {
			return authorityFail("integer_bound")
		}
		return nil
	}
}
func arEnum(values ...string) authorityRule {
	return func(v any) error {
		if v == nil {
			return authorityFail("null_member")
		}
		s, ok := v.(string)
		if !ok {
			return authorityFail("wrong_type")
		}
		for _, x := range values {
			if x == s {
				return nil
			}
		}
		return authorityFail("wrong_domain")
	}
}
func arLiteral(n int64, code string) authorityRule {
	return func(v any) error {
		if v != n {
			return authorityFail(code)
		}
		return nil
	}
}
func arArray(r authorityRule, max int) authorityRule {
	return func(v any) error {
		if v == nil {
			return authorityFail("null_member")
		}
		a, ok := v.([]any)
		if !ok {
			return authorityFail("wrong_type")
		}
		if len(a) > max {
			return authorityFail("array_limit")
		}
		for i, x := range a {
			if e := r(x); e != nil {
				return fmt.Errorf("[%d]: %w", i, e)
			}
		}
		return nil
	}
}
func arBool(v any) error {
	if _, ok := v.(bool); !ok {
		return authorityFail("wrong_type")
	}
	return nil
}
func arText(v any) error {
	s, ok := v.(string)
	if !ok {
		return authorityFail("wrong_type")
	}
	if len(s) < 1 || len(s) > 255 {
		return authorityFail("field_limit")
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return authorityFail("field_limit")
		}
	}
	return nil
}
func arPattern(pattern string) authorityRule {
	r := regexp.MustCompile(pattern)
	return func(v any) error {
		s, ok := v.(string)
		if !ok {
			return authorityFail("wrong_type")
		}
		if !r.MatchString(s) {
			return authorityFail("field_format")
		}
		return nil
	}
}

var (
	arN    = arInt(1, authoritySafeInteger)
	arZ    = arInt(0, authoritySafeInteger)
	arUID  = arInt(0, 4294967295)
	arD    = arPattern(`^sha256:[0-9a-f]{64}$`)
	arH    = arPattern(`^[0-9a-f]{64}$`)
	arID   = arPattern(`^[0-9a-f]{32}$`)
	arBoot = arPattern(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

func arToken(v any) error {
	if e := arID(v); e != nil {
		return e
	}
	if v == strings.Repeat("0", 32) {
		return authorityFail("field_format")
	}
	return nil
}
func arStamp(v any) error {
	s, ok := v.(string)
	if !ok {
		return authorityFail("wrong_type")
	}
	x, e := time.Parse("2006-01-02T15:04:05Z", s)
	if e != nil || len(s) != 20 || x.Year() < 1970 || x.Format("2006-01-02T15:04:05Z") != s {
		return authorityFail("field_format")
	}
	return nil
}
func arSized(r authorityRule, cap int) authorityRule {
	return func(v any) error {
		if e := r(v); e != nil {
			return e
		}
		_, e := marshalAuthorityCCJ(v.(map[string]any), cap)
		return e
	}
}
func arWith(r authorityRule, check func(map[string]any) error) authorityRule {
	return func(v any) error {
		if e := r(v); e != nil {
			return e
		}
		return check(v.(map[string]any))
	}
}
func arBlob(cap int64) authorityRule {
	return arObject(map[string]authorityRule{"hash": arH, "bytes": arInt(1, cap)})
}
func arCheckpoint() authorityRule {
	return arWith(arObject(map[string]authorityRule{"seq": arZ, "hash": arH}), func(o map[string]any) error {
		if o["seq"] == int64(0) && o["hash"] != strings.Repeat("0", 64) {
			return authorityFail("empty_checkpoint_hash")
		}
		return nil
	})
}

var authorityRoles = map[string]string{"payload": "keymaker-private/3", "pin_policy": "pin-config/1", "enrollment_snapshot": "registrar-snapshot/1", "high_water": "registry-high-water/1", "approval_history": "keymaker-approval-history/1", "message_inventory": "keymaker-message-inventory/3", "native_inventory": "keymaker-native-inventory/3", "migration_history": "keymaker-migration-history/1", "manager_inventory": "pc2-manager-inventory/1", "recovery_history": "pc2-recovery-history/1"}

func arMeta(codec string, cap int64) authorityRule {
	return arObject(map[string]authorityRule{"codec": arEnum(codec), "digest": arD, "bytes": arInt(1, cap)})
}
func arRef() authorityRule {
	return arWith(arObject(map[string]authorityRule{"role": arText, "codec": arText, "digest": arD, "bytes": arInt(1, stateBudget), "verity_digest": arPattern(`^fsverity-sha256:[0-9a-f]{64}$`), "device": arObject(map[string]authorityRule{"major": arUID, "minor": arUID}), "inode": arPattern(`^[0-9a-f]{16}$`), "uid": arUID, "mode": arEnum("0600", "0640")}), func(o map[string]any) error {
		role := o["role"].(string)
		codec, ok := authorityRoles[role]
		if !ok {
			return authorityFail("outside_read_set")
		}
		if codec != o["codec"] {
			return authorityFail("wrong_domain")
		}
		if o["inode"] == "0000000000000000" {
			return authorityFail("field_format")
		}
		root := role == "pin_policy" || role == "manager_inventory" || role == "recovery_history"
		if root && (o["uid"] != int64(0) || o["mode"] != "0640") || !root && o["mode"] != "0600" {
			return authorityFail("participant_owner")
		}
		return nil
	})
}
func arEffect() authorityRule {
	return arObject(map[string]authorityRule{"caller_uid": arUID, "caller_generation": arToken, "request_id": arID})
}
func arEntry() authorityRule {
	return arObject(map[string]authorityRule{"uid": arUID, "generation": arToken, "predecessor_generation": arToken, "registration_number": arN, "master_epoch": arText, "owner": arText, "provision_effect": arEffect(), "provision_pin_digest": arD, "pin_policy_digest": arD, "admitted": arBool, "binding_status": arEnum("provisioned", "active", "unbound", "revoked")})
}
func arEntries(v any) error {
	if e := arArray(arEntry(), 4096)(v); e != nil {
		return e
	}
	var last int64
	live := map[string]bool{}
	for _, x := range v.([]any) {
		r := x.(map[string]any)
		n := r["registration_number"].(int64)
		if n <= last {
			return authorityFail("entry_order")
		}
		last = n
		if r["binding_status"] == "active" || r["binding_status"] == "provisioned" {
			key := fmt.Sprint(r["uid"]) + "/" + r["generation"].(string)
			if live[key] {
				return authorityFail("duplicate_live_tuple")
			}
			live[key] = true
		}
	}
	return nil
}
func arFactFields() map[string]authorityRule {
	return map[string]authorityRule{"authority_incarnation": arToken, "instance_id": arID, "boot_id": arBoot, "master_epoch": arText, "pin_policy_digest": arD, "registry_digest": arD, "custody_ready": arBool, "withdrawal_counter": arN, "journal": arCheckpoint(), "entries": arEntries}
}
func arRoot(kind authorityKind) authorityRule {
	fields := arFactFields()
	fields["version"] = arEnum("keymaker-authority/2")
	fields["minimum_reader_schema"] = arLiteral(3, "floor_rollback")
	fields["transaction_revision"] = arN
	fields["previous_root_digest"] = arNullable(arD)
	fields["recovery"] = arEnum("clear")
	fields["payload"] = arRef()
	fields["participants"] = arMeta("keymaker-participants/1", 65536)
	fields["provenance"] = arMeta("keymaker-provenance/1", 4096)
	fields["reservation"] = arMeta("keymaker-reservation/1", 65536)
	fields["manager_baseline"] = arObject(map[string]authorityRule{"revision": arN, "digest": arD})
	if kind != authorityBodyFieldsKind {
		fields["binding_commit"] = arObject(map[string]authorityRule{"version": arN, "digest": arH, "audit_seq": arN, "audit_hash": arH})
	}
	if kind == authorityRootKind {
		fields["root_digest"] = arD
	}
	return arSized(arWith(arObject(fields), func(o map[string]any) error {
		if o["payload"].(map[string]any)["role"] != "payload" {
			return authorityFail("wrong_domain")
		}
		if b, ok := o["binding_commit"].(map[string]any); ok && b["version"] != o["transaction_revision"] {
			return authorityFail("revision_mismatch")
		}
		if o["journal"].(map[string]any)["seq"] == int64(0) && len(o["entries"].([]any)) != 0 {
			return authorityFail("empty_journal_uid")
		}
		return nil
	}), authorityRootLimit)
}
func arParticipants() authorityRule {
	return arWith(arObject(map[string]authorityRule{"version": arEnum("keymaker-participants/1"), "files": arArray(arRef(), 11)}), func(o map[string]any) error {
		a := o["files"].([]any)
		if len(a) != 10 {
			return authorityFail("outside_read_set")
		}
		last := ""
		seen := map[string]bool{}
		for _, x := range a {
			r := x.(map[string]any)
			role := r["role"].(string)
			if role <= last {
				return authorityFail("participant_order")
			}
			last = role
			key := fmt.Sprint(r["device"]) + "/" + r["inode"].(string)
			if seen[key] {
				return authorityFail("participant_alias")
			}
			seen[key] = true
		}
		return nil
	})
}
func arReservation() authorityRule {
	row := arObject(map[string]authorityRule{"owner": arEnum("keymaker", "manager"), "kind": arText, "inventory_digest": arD, "materialized_bytes": arInt(0, stateBudget), "integrity_bytes": arInt(0, stateBudget), "reserved_bytes": arInt(0, stateBudget), "objects": arInt(0, stateBudget)})
	return arWith(arObject(map[string]authorityRule{"version": arEnum("keymaker-reservation/1"), "base_root_digest": arNullable(arD), "limit_bytes": arLiteral(stateBudget, "not_aggregate"), "groups": arArray(row, 14), "total_bytes": arInt(0, stateBudget), "audit_records_reserved": arLiteral(8, "not_aggregate"), "manager_slots": arObject(map[string]authorityRule{"slots": arLiteral(1, "not_aggregate"), "attempt_bytes": arLiteral(4096, "not_aggregate"), "hold_bytes": arLiteral(4096, "not_aggregate"), "guard_bytes": arLiteral(65536, "not_aggregate"), "recovery_bytes": arLiteral(65536, "not_aggregate")})}), func(o map[string]any) error {
		want := strings.Fields("keymaker/artifacts keymaker/installed keymaker/migration_history keymaker/pending_proofs keymaker/policy_history keymaker/recovery keymaker/reservation_metadata keymaker/root_history keymaker/staging manager/attempts manager/holds manager/inventory manager/recovery manager/staging")
		a := o["groups"].([]any)
		if len(a) != len(want) {
			return authorityFail("not_aggregate")
		}
		var total int64
		for i, x := range a {
			r := x.(map[string]any)
			if r["owner"].(string)+"/"+r["kind"].(string) != want[i] {
				return authorityFail("not_aggregate")
			}
			total += r["materialized_bytes"].(int64) + r["integrity_bytes"].(int64) + r["reserved_bytes"].(int64)
		}
		if total > stateBudget || o["total_bytes"] != total {
			return authorityFail("not_aggregate")
		}
		return nil
	})
}

func authorityAnchorRule() authorityRule {
	return arWith(arObject(map[string]authorityRule{"registry_id": arKey, "owner": arOwner, "publication_seq": arZ, "freshness_id": arNullable(arD), "issued_at": arNullable(arStamp), "snapshot": arD, "registry_seq": arN, "checkpoint_id": arD}), func(o map[string]any) error {
		zero := o["publication_seq"] == int64(0)
		if (o["freshness_id"] == nil) != zero || (o["issued_at"] == nil) != zero {
			return authorityFail("freshness_state_invalid")
		}
		return nil
	})
}
func arWitness() authorityRule {
	return arObject(map[string]authorityRule{"registry_id": arKey, "owner": arOwner, "registry_seq": arN, "registry_head": arD, "checkpoint_id": arD, "previous_checkpoint_id": arNullable(arD)})
}
func authorityJournalRule() authorityRule {
	inputs := arObject(map[string]authorityRule{"entries": arArray(arBlob(8192), 64), "checkpoints": arArray(arBlob(8192), 2), "snapshot": arBlob(8192), "witness": arWitness()})
	prior := arNullable(func(v any) error {
		if e := arBlob(8192)(v); e != nil {
			if authorityCode(e) == "integer_bound" {
				return authorityFail("prior_limit")
			}
			return e
		}
		return nil
	})
	return arSized(arWith(arObject(map[string]authorityRule{"transaction": arID, "inputs": inputs, "prior_checkpoint": prior, "policy": arBlob(65536), "read_evidence": arBlob(stateBudget), "watermark": arStamp}), func(o map[string]any) error {
		i := o["inputs"].(map[string]any)
		entries := i["entries"].([]any)
		checks := i["checkpoints"].([]any)
		if len(entries) < 1 || len(checks) < 1 {
			return authorityFail("journal_unavailable")
		}
		var n int64
		for _, a := range [][]any{entries, checks} {
			for _, v := range a {
				n += v.(map[string]any)["bytes"].(int64)
			}
		}
		if n > 540672 {
			return authorityFail("total_limit")
		}
		return nil
	}), 65536)
}
func authorityMessageRule() authorityRule {
	scope := arObject(map[string]authorityRule{"anchor": authorityAnchorRule(), "policy": arBlob(65536), "checkpoint": arBlob(8192), "snapshot": arBlob(8192), "artifact": arNullable(arBlob(65536))})
	fresh := arObject(map[string]authorityRule{"transaction": arID, "phase": arEnum("prepared", "committed", "aborted", "unknown"), "artifact": arBlob(65536)})
	return arWith(arObject(map[string]authorityRule{"version": arEnum("keymaker-message-authority/1"), "watermark": arNullable(arStamp), "scopes": arArray(scope, 65536), "journals": arArray(authorityJournalRule(), 65536), "freshness": arArray(fresh, 65536)}), func(o map[string]any) error {
		empty := true
		ids := map[string]bool{}
		last := ""
		for _, x := range o["scopes"].([]any) {
			empty = false
			r := x.(map[string]any)
			a := r["anchor"].(map[string]any)
			key := a["registry_id"].(string) + "/" + a["owner"].(string)
			if key <= last {
				return authorityFail("inventory_order")
			}
			last = key
			if (r["artifact"] == nil) != (a["publication_seq"] == int64(0)) {
				return authorityFail("freshness_state_invalid")
			}
		}
		for _, name := range []string{"journals", "freshness"} {
			last = ""
			for _, x := range o[name].([]any) {
				empty = false
				id := x.(map[string]any)["transaction"].(string)
				if id <= last || ids[id] {
					return authorityFail("inventory_order")
				}
				last = id
				ids[id] = true
			}
		}
		if (o["watermark"] == nil) != empty {
			return authorityFail("freshness_state_invalid")
		}
		return nil
	})
}
func authorityFreshnessRule() authorityRule {
	endpoint := arObject(map[string]authorityRule{"freshness": arBlob(8192), "checkpoint": arBlob(8192)})
	oldEndpoint := arObject(map[string]authorityRule{"freshness": arNullable(arBlob(8192)), "checkpoint": arBlob(8192)})
	audit := arObject(map[string]authorityRule{"registry_id": arKey, "owner": arOwner, "snapshot_id": arD, "checkpoint_id": arD, "freshness_id": arD, "reanchored": arBool, "old_freshness_id": arNullable(arD), "old_checkpoint_id": arNullable(arD)})
	reanchor := arObject(map[string]authorityRule{"reanchored": func(v any) error {
		if v != true {
			return authorityFail("wrong_type")
		}
		return nil
	}, "skipped_publications": arZ, "old_freshness_id": arD, "new_freshness_id": arD, "old_checkpoint_id": arD, "new_checkpoint_id": arD})
	return arWith(arObject(map[string]authorityRule{"kind": arEnum("message-freshness/1"), "transaction": arID, "mode": arEnum("normal", "reanchor"), "policy": arBlob(65536), "old_anchor": authorityAnchorRule(), "new_anchor": authorityAnchorRule(), "watermark_before": arStamp, "watermark_after": arStamp, "witness": arWitness(), "witness_read_at": arStamp, "proof": arArray(arBlob(8192), 64), "checkpoint": arBlob(8192), "snapshot": arBlob(8192), "endpoints": arObject(map[string]authorityRule{"old": oldEndpoint, "new": endpoint}), "receipt_audit": arNullable(audit), "reanchor": arNullable(reanchor)}), func(o map[string]any) error {
		old := o["old_anchor"].(map[string]any)
		next := o["new_anchor"].(map[string]any)
		if o["watermark_after"].(string) < o["watermark_before"].(string) {
			return authorityFail("watermark_rollback")
		}
		if old["registry_id"] != next["registry_id"] || old["owner"] != next["owner"] {
			return authorityFail("freshness_state_invalid")
		}
		if next["publication_seq"].(int64) <= old["publication_seq"].(int64) || next["issued_at"] == nil || old["issued_at"] != nil && next["issued_at"].(string) <= old["issued_at"].(string) {
			return authorityFail("freshness_state_invalid")
		}
		e := o["endpoints"].(map[string]any)
		if old["publication_seq"] != int64(0) && e["old"].(map[string]any)["freshness"] == nil {
			return authorityFail("endpoint_missing")
		}
		if len(o["proof"].([]any)) == 0 {
			return authorityFail("missing_member")
		}
		var total int64
		for _, x := range o["proof"].([]any) {
			total += x.(map[string]any)["bytes"].(int64)
		}
		total += o["checkpoint"].(map[string]any)["bytes"].(int64)
		if total > 532480 {
			return authorityFail("total_limit")
		}
		r := o["reanchor"]
		if o["mode"] == "normal" {
			if r != nil {
				return authorityFail("freshness_state_invalid")
			}
		} else {
			if r == nil {
				return authorityFail("missing_member")
			}
			rr := r.(map[string]any)
			if old["publication_seq"] == int64(0) || rr["skipped_publications"] != next["publication_seq"].(int64)-old["publication_seq"].(int64)-1 {
				return authorityFail("skip_mismatch")
			}
			if rr["old_freshness_id"] != old["freshness_id"] || rr["new_freshness_id"] != next["freshness_id"] || rr["old_checkpoint_id"] != old["checkpoint_id"] || rr["new_checkpoint_id"] != next["checkpoint_id"] {
				return authorityFail("freshness_state_invalid")
			}
		}
		if a, ok := o["receipt_audit"].(map[string]any); ok {
			if a["registry_id"] != next["registry_id"] || a["owner"] != next["owner"] || a["snapshot_id"] != next["snapshot"] || a["checkpoint_id"] != next["checkpoint_id"] || a["freshness_id"] != next["freshness_id"] || a["reanchored"] != (o["mode"] == "reanchor") {
				return authorityFail("freshness_state_invalid")
			}
			if o["mode"] == "normal" && (a["old_freshness_id"] != nil || a["old_checkpoint_id"] != nil) {
				return authorityFail("freshness_state_invalid")
			}
			if o["mode"] == "reanchor" && (a["old_freshness_id"] != old["freshness_id"] || a["old_checkpoint_id"] != old["checkpoint_id"]) {
				return authorityFail("freshness_state_invalid")
			}
		}
		return nil
	})
}
func arS2(t reflect.Type) authorityRule {
	return func(v any) error {
		b, e := canonical(v)
		if e != nil {
			return e
		}
		if e = messageRequired(b, t); e != nil {
			return authorityFail("s2_shape")
		}
		target := reflect.New(t).Interface()
		if e = StrictJSON(bytes.NewReader(b), target); e != nil {
			return authorityFail("s2_shape")
		}
		return nil
	}
}
func authorityPrivateRule() authorityRule {
	binding := authorityBindingRule()
	request := authorityRequestRule()
	dispatch := arObject(map[string]authorityRule{"transaction": arID, "codec": arEnum("keymaker-msg-state/2", "keymaker-message-artifact/3", "message-freshness/1")})
	return arWith(arObject(map[string]authorityRule{"version": arEnum("keymaker-private/3"), "next_registration_number": arN, "records": arArray(binding, 65536), "requests": arArray(request, 65536), "transaction_revision": arN, "messages": authorityMessagesRule(), "message_dispatch": arArray(dispatch, 65536), "message_authority": authorityMessageRule()}), func(o map[string]any) error {
		if e := authorityPrivateHistory(o); e != nil {
			return e
		}
		last := ""
		by := map[string]string{}
		for _, x := range o["message_dispatch"].([]any) {
			r := x.(map[string]any)
			id := r["transaction"].(string)
			if id <= last {
				return authorityFail("inventory_order")
			}
			last = id
			by[id] = r["codec"].(string)
		}
		a := o["message_authority"].(map[string]any)
		expected := map[string]bool{}
		for _, x := range o["messages"].(map[string]any)["transactions"].([]any) {
			id, ok := x.(map[string]any)["id"].(string)
			if !ok || expected[id] {
				return authorityFail("dispatch_mismatch")
			}
			expected[id] = true
			if by[id] != "keymaker-msg-state/2" && by[id] != "keymaker-message-artifact/3" {
				return authorityFail("dispatch_mismatch")
			}
		}
		for _, x := range a["freshness"].([]any) {
			id := x.(map[string]any)["transaction"].(string)
			if expected[id] {
				return authorityFail("dispatch_mismatch")
			}
			expected[id] = true
		}
		if len(expected) != len(by) {
			return authorityFail("dispatch_mismatch")
		}
		for _, x := range a["freshness"].([]any) {
			if by[x.(map[string]any)["transaction"].(string)] != "message-freshness/1" {
				return authorityFail("dispatch_mismatch")
			}
		}
		return nil
	})
}
func authorityAttemptRule(kind authorityKind) authorityRule {
	fields := map[string]authorityRule{"version": arEnum("pc2-activation-attempt/1"), "manager_id": arID, "effect_digest": arD, "target": arObject(map[string]authorityRule{"uid": arUID, "generation": arToken, "registration_number": arN, "master_epoch": arText, "predecessor_generation": arToken}), "owner": arText, "provision_effect": arEffect(), "ordinal": arN, "source": arObject(map[string]authorityRule{"transaction_revision": arN, "root_digest": arD, "authority_incarnation": arToken, "withdrawal_counter": arN}), "prepared_tail": arCheckpoint(), "active_record_hash": arH, "boot_id": arBoot, "instance_id": arID}
	if kind != authorityAttemptPreimageKind {
		fields["attempt_id"] = arD
		fields["disposition"] = arEnum("pending", "absent", "durable")
		fields["evidence_digest"] = arNullable(arD)
	}
	return arWith(arObject(fields), func(o map[string]any) error {
		if o["prepared_tail"].(map[string]any)["seq"] == int64(0) {
			return authorityFail("activation_requires_positive_tail")
		}
		if kind != authorityAttemptPreimageKind && (o["evidence_digest"] == nil) != (o["disposition"] == "pending") {
			return authorityFail("evidence_mismatch")
		}
		return nil
	})
}
func authorityRecoveryRule() authorityRule {
	return arWith(arObject(map[string]authorityRule{"version": arEnum("pc2-recovery-record/1"), "recovery_id": arID, "previous_digest": arNullable(arD), "phase": arEnum("open", "resolved", "release-prepared", "released"), "holds": arArray(arD, 1), "root_digest": arD, "journal": arCheckpoint(), "outcome": arEnum("unknown", "absent", "durable"), "evidence_digest": arNullable(arD)}), func(o map[string]any) error {
		if len(o["holds"].([]any)) != 1 {
			return authorityFail("missing_member")
		}
		if (o["evidence_digest"] == nil) != (o["outcome"] == "unknown") {
			return authorityFail("evidence_mismatch")
		}
		if (o["phase"] == "open") != (o["outcome"] == "unknown") {
			return authorityFail("recovery_phase")
		}
		return nil
	})
}
func authorityGuardRule() authorityRule {
	hold := arObject(map[string]authorityRule{"kind": arEnum("activation", "authority"), "origin_id": arD, "hold_id": arD})
	return arWith(arObject(map[string]authorityRule{"version": arEnum("pc2-recovery-guard/1"), "revision": arN, "previous_digest": arNullable(arD), "inventory": arMeta("pc2-manager-inventory/1", 65536), "phase": arEnum("clear", "open", "resolved", "release-prepared", "released"), "holds": arArray(hold, 1), "attempt": arNullable(arMeta("pc2-activation-attempt/1", 4096)), "resolution": arNullable(arMeta("pc2-recovery-record/1", 8192)), "release_prepared": arNullable(arMeta("pc2-recovery-record/1", 8192)), "released": arNullable(arMeta("pc2-recovery-record/1", 8192)), "source_root_digest": arD}), func(o map[string]any) error {
		a := o["holds"].([]any)
		phase := o["phase"].(string)
		if phase == "clear" {
			if len(a) != 0 || o["attempt"] != nil || o["resolution"] != nil || o["release_prepared"] != nil || o["released"] != nil {
				return authorityFail("recovery_phase")
			}
			return nil
		}
		if len(a) != 1 {
			return authorityFail("missing_member")
		}
		if (o["attempt"] != nil) != (a[0].(map[string]any)["kind"] == "activation") {
			return authorityFail("recovery_phase")
		}
		rank := map[string]int{"open": 0, "resolved": 1, "release-prepared": 2, "released": 3}[phase]
		for i, k := range []string{"resolution", "release_prepared", "released"} {
			if (o[k] != nil) != (i < rank) {
				return authorityFail("recovery_phase")
			}
		}
		return nil
	})
}

func authorityRuleFor(kind authorityKind) authorityRule {
	switch kind {
	case authorityRootKind, authorityRootPreimageKind, authorityBodyFieldsKind:
		return arRoot(kind)
	case authoritySnapshotKind:
		return arWith(arObject(map[string]authorityRule{"schema_version": arLiteral(3, "wrong_domain"), "authority": arRoot(authorityRootKind), "payload": arRef(), "audit_seq": arN, "audit_hash": arH}), func(o map[string]any) error {
			r := o["authority"].(map[string]any)
			c := r["binding_commit"].(map[string]any)
			if !reflect.DeepEqual(o["payload"], r["payload"]) || o["audit_seq"] != c["audit_seq"] || o["audit_hash"] != c["audit_hash"] {
				return authorityFail("snapshot_mismatch")
			}
			return verifyAuthorityRoot(r)
		})
	case "keymaker-private/3":
		return authorityPrivateRule()
	case "keymaker-participants/1":
		return arParticipants()
	case "keymaker-authority-facts/1":
		f := arFactFields()
		f["version"] = arEnum("keymaker-authority-facts/1")
		return arObject(f)
	case "keymaker-provenance/1":
		return arObject(map[string]authorityRule{"version": arEnum(string(kind)), "base_root_digest": arNullable(arD), "facts_digest": arD, "participants_digest": arD, "journal": arCheckpoint()})
	case "keymaker-reservation/1":
		return arReservation()
	case "keymaker-combined-body/3":
		return arWith(arObject(map[string]authorityRule{"type": arEnum(string(kind)), "schema_version": arLiteral(3, "wrong_domain"), "authority": arRoot(authorityBodyFieldsKind), "payload": arRef()}), func(o map[string]any) error {
			if !reflect.DeepEqual(o["payload"], o["authority"].(map[string]any)["payload"]) {
				return authorityFail("snapshot_mismatch")
			}
			return nil
		})
	case "keymaker-authority-candidate/1":
		return arObject(map[string]authorityRule{"type": arEnum(string(kind)), "body_digest": arD})
	case "keymaker-authority-tx/1":
		return arObject(map[string]authorityRule{"type": arEnum(string(kind)), "base_root_digest": arNullable(arD), "next_revision": arN, "candidate_root_digest": arD})
	case "pc2-activation-attempt/1", authorityAttemptPreimageKind:
		return authorityAttemptRule(kind)
	case "pc2-hold/1":
		return arObject(map[string]authorityRule{"type": arEnum(string(kind)), "kind": arEnum("activation", "authority"), "origin_id": arD})
	case "keymaker-authority-link/1":
		return arObject(map[string]authorityRule{"type": arEnum(string(kind)), "root_digest": arD, "transaction_revision": arN, "authority_incarnation": arToken, "withdrawal_counter": arN, "journal": arCheckpoint(), "guard_digest": arD, "minimum_reader_schema": arLiteral(3, "floor_rollback"), "floor_epoch": arN})
	case "keymaker-authority-floor/1":
		return arObject(map[string]authorityRule{"version": arEnum(string(kind)), "root_digest": arD, "transaction_revision": arN, "authority_incarnation": arToken, "withdrawal_counter": arN, "journal": arCheckpoint(), "guard_digest": arD, "minimum_reader_schema": arLiteral(3, "floor_rollback"), "epoch": arN, "logical_link_digest": arD})
	case "pc2-manager-inventory/1":
		return arObject(map[string]authorityRule{"version": arEnum(string(kind)), "revision": arN, "previous_digest": arNullable(arD), "attempts_digest": arD, "holds_digest": arD, "recovery_digest": arD, "materialized_bytes": arInt(0, stateBudget), "objects": arInt(0, stateBudget), "slot_reservation": arD})
	case "pc2-recovery-guard/1":
		return authorityGuardRule()
	case "pc2-recovery-record/1":
		return authorityRecoveryRule()
	case "keymaker-authority-intent/1":
		return func(v any) error {
			o, ok := v.(map[string]any)
			if !ok {
				return authorityFail("wrong_type")
			}
			f := map[string]authorityRule{"version": arEnum(string(kind)), "state": arEnum("clear", "pending")}
			if o["state"] == "clear" {
				f["last_transaction"] = arD
			} else {
				f["transaction_id"] = arD
				f["base_root_digest"] = arNullable(arD)
				f["candidate_root_digest"] = arD
				f["new_root_digest"] = arD
				f["next_revision"] = arN
				f["participants_digest"] = arD
				f["reservation_digest"] = arD
			}
			return arObject(f)(v)
		}
	case "keymaker-capacity-inventory/1":
		return arWith(arObject(map[string]authorityRule{"version": arEnum(string(kind)), "owner": arEnum("keymaker", "manager"), "kind": arText, "objects": arArray(arObject(map[string]authorityRule{"id": arText, "bytes": arInt(1, stateBudget), "integrity_bytes": arInt(0, stateBudget)}), 1048576)}), func(o map[string]any) error {
			if !authorityClass(o["owner"].(string), o["kind"].(string)) {
				return authorityFail("not_aggregate")
			}
			last := ""
			var total int64
			for _, x := range o["objects"].([]any) {
				r := x.(map[string]any)
				if r["id"].(string) <= last {
					return authorityFail("inventory_order")
				}
				last = r["id"].(string)
				total += r["bytes"].(int64) + r["integrity_bytes"].(int64)
				if total > stateBudget {
					return authorityFail("not_aggregate")
				}
			}
			return nil
		})
	case "keymaker-capacity-genesis/1":
		return arObject(map[string]authorityRule{"version": arEnum(string(kind)), "authority_incarnation": arToken, "minimum_reader_schema": arLiteral(3, "floor_rollback"), "epoch": arN, "reservation": arMeta("keymaker-reservation/1", 65536), "authorization": arBlob(65536)})
	case "keymaker-migration/1":
		return arWith(arObject(map[string]authorityRule{"version": arEnum(string(kind)), "migration_id": arID, "input_schema": func(v any) error {
			if v != int64(1) && v != int64(2) {
				return authorityFail("wrong_domain")
			}
			return nil
		}, "phase": arEnum("legacy_validated", "s2_staged", "s2_committed", "combined_staged", "combined_committed", "released"), "minimum_reader_schema": arLiteral(3, "floor_rollback"), "base_digest": arD, "s2_digest": arH, "combined_candidate_digest": arNullable(arD), "parent_intent_digest": arD}), func(o map[string]any) error {
			early := o["phase"] == "legacy_validated" || o["phase"] == "s2_staged" || o["phase"] == "s2_committed"
			if (o["combined_candidate_digest"] == nil) != early {
				return authorityFail("migration_phase")
			}
			return nil
		})
	case "keymaker-approval-history/1", "keymaker-migration-history/1", "pc2-recovery-history/1", "keymaker-message-inventory/3":
		return authorityHistoryRule(kind)
	case "keymaker-native-inventory/3":
		return arObject(map[string]authorityRule{"version": arEnum(string(kind)), "entries": arArray(arObject(map[string]authorityRule{"caller": arObject(map[string]authorityRule{"uid": arUID, "generation": arToken}), "request_id": arID, "method": arText, "arguments_digest": arD, "result_digest": arD, "status": arEnum("pending", "committed")}), 65536)})
	case "keymaker-message-authority/1":
		return authorityMessageRule()
	case "message-freshness/1":
		return authorityFreshnessRule()
	case "keymaker-message-policy/1":
		return arObject(map[string]authorityRule{"version": arEnum(string(kind)), "registry_root": arObject(map[string]authorityRule{"key": arKey, "purpose": arEnum("registry-revocation"), "attestation_root": arKey}), "owner": arOwner, "max_age": arInt(1, 60), "freshness_margin_seconds": arInt(0, 60), "scope": arBlob(stateBudget), "cumulative": arBlob(stateBudget), "restore": arBlob(stateBudget), "time": arBlob(stateBudget), "reanchor_approval": arNullable(arBlob(stateBudget))})
	case "keymaker-message-artifact/3":
		return func(v any) error {
			o, ok := v.(map[string]any)
			if !ok {
				return authorityFail("wrong_type")
			}
			var body authorityRule
			switch o["kind"] {
			case "intent":
				body = authorityIntentRule()
			case "candidate":
				body = authorityCandidateRule()
			case "resolution":
				body = authorityResolutionRule()
			default:
				return authorityFail("wrong_domain")
			}
			return arObject(map[string]authorityRule{"version": arEnum(string(kind)), "kind": arEnum("intent", "candidate", "resolution"), "body": body})(v)
		}
	default:
		return func(any) error { return authorityFail("wrong_domain") }
	}
}
func authorityClass(owner, kind string) bool {
	want := map[string]string{"keymaker": " installed artifacts recovery staging pending_proofs policy_history root_history migration_history reservation_metadata ", "manager": " attempts holds recovery inventory staging "}
	return strings.Contains(want[owner], " "+kind+" ")
}
func authorityHistoryRule(kind authorityKind) authorityRule {
	max := 65536
	if kind == "keymaker-message-inventory/3" {
		max = 1048576
	}
	row := arObject(map[string]authorityRule{"kind": arEnum("legacy_snapshot", "s2_snapshot", "combined_payload", "capacity_genesis", "message2", "message3", "approval", "freshness", "signed_input", "message_policy", "policy", "migration", "attempt", "hold", "recovery"), "id": arText, "digest": arD, "bytes": arInt(1, stateBudget)})
	return arWith(arObject(map[string]authorityRule{"version": arEnum(string(kind)), "entries": arArray(row, max)}), func(o map[string]any) error {
		last := ""
		for _, x := range o["entries"].([]any) {
			r := x.(map[string]any)
			key := r["kind"].(string) + "/" + r["id"].(string)
			if key <= last {
				return authorityFail("inventory_order")
			}
			last = key
		}
		return nil
	})
}
func decodeAuthority(raw []byte, kind authorityKind) (map[string]any, error) {
	o, e := parseAuthorityCCJ(raw, authorityLimit(kind))
	if e != nil {
		return nil, e
	}
	if e = authorityRuleFor(kind)(o); e != nil {
		return nil, e
	}
	switch kind {
	case authorityRootKind:
		e = verifyAuthorityRoot(o)
	case "pc2-activation-attempt/1":
		var id string
		id, e = authorityAttemptID(o)
		if e == nil && o["attempt_id"] != id {
			e = authorityFail("attempt_id_mismatch")
		}
	}
	if e != nil {
		return nil, e
	}
	return o, nil
}
func encodeAuthority(o map[string]any, kind authorityKind) ([]byte, error) {
	if e := authorityRuleFor(kind)(o); e != nil {
		return nil, e
	}
	b, e := marshalAuthorityCCJ(o, authorityLimit(kind))
	if e != nil {
		return nil, e
	}
	if _, e = decodeAuthority(b, kind); e != nil {
		return nil, e
	}
	return b, nil
}

func arKey(v any) error {
	s, ok := v.(string)
	if !ok {
		return authorityFail("wrong_type")
	}
	if record.ValidateKey(s) != nil {
		return authorityFail("field_format")
	}
	return nil
}
func arOwner(v any) error {
	if e := arText(v); e != nil {
		return e
	}
	return nil
}

// Retained argument/result bytes use their original native CCJ schema, including
// explicit pending-result null. They are payload data, never logical-root fields.
func authorityRequestRule() authorityRule {
	args := func(v any) error {
		s, ok := v.(string)
		if !ok {
			return authorityFail("wrong_type")
		}
		if len(s) > control.MaxFrame {
			return authorityFail("field_limit")
		}
		if _, e := control.Decode([]byte(s)); e != nil {
			return authorityFail("native_arguments")
		}
		return nil
	}
	result := func(v any) error {
		if v == nil {
			return nil
		}
		o, ok := v.(map[string]any)
		if !ok {
			return authorityFail("wrong_type")
		}
		if _, e := marshalAuthorityCCJ(o, control.MaxFrame); e != nil {
			return e
		}
		return nil
	}
	return arWith(arObject(map[string]authorityRule{"caller": arObject(map[string]authorityRule{"uid": arUID, "generation": arToken}), "id": arID, "method": arEnum("hello", "pubkey", "register", "revoke", "sign_registration"), "arguments": args, "status": arEnum("pending", "committed"), "result": result}), func(o map[string]any) error {
		if o["status"] == "pending" {
			if !mutation(o["method"].(string)) || o["result"] != nil {
				return authorityFail("native_result")
			}
		} else if o["result"] == nil {
			return authorityFail("native_result")
		}
		return nil
	})
}
func authorityPrivateHistory(o map[string]any) error {
	next := o["next_registration_number"].(int64)
	var last int64
	live := map[string]bool{}
	paths := map[string]map[string]any{}
	for _, x := range o["records"].([]any) {
		r := x.(map[string]any)
		n := r["registration_number"].(int64)
		if n <= last || n >= next {
			return authorityFail("binding_history")
		}
		last = n
		p := fmt.Sprint(r["uid"]) + "/" + r["generation"].(string)
		if r["status"] == "active" || r["status"] == "provisioned" {
			if live[p] {
				return authorityFail("binding_history")
			}
			live[p] = true
		}
		key := r["master_epoch"].(string) + ":" + r["path"].(string)
		if old := paths[key]; old != nil {
			if old["status"] != "unbound" || old["lifetime"] != "persistent" || old["owner"] != r["owner"] || old["lifetime"] != r["lifetime"] {
				return authorityFail("binding_history")
			}
		}
		paths[key] = r
	}
	ids := map[string]bool{}
	for _, x := range o["requests"].([]any) {
		r := x.(map[string]any)
		caller := r["caller"].(map[string]any)
		key := fmt.Sprint(caller["uid"]) + "/" + caller["generation"].(string) + "/" + r["id"].(string)
		if ids[key] {
			return authorityFail("duplicate_request")
		}
		ids[key] = true
	}
	return nil
}

func authorityMessageBindingRule() authorityRule {
	return arWith(arObject(map[string]authorityRule{"uid": arInt(0, 4294967294), "generation": arToken, "registration_number": arN, "master_epoch": arText, "owner": arText, "path": arText}), func(o map[string]any) error {
		if ValidatePath(o["path"].(string), "swarma-msg") != "" {
			return authorityFail("field_format")
		}
		return nil
	})
}
func authorityCertificateRule() authorityRule {
	return arWith(arS2(reflect.TypeFor[messageCertificate]()), func(o map[string]any) error {
		if e := authorityMessageBindingRule()(o["binding"]); e != nil {
			return e
		}
		if e := arID(o["transaction"]); e != nil {
			return e
		}
		s, ok := o["envelope"].(string)
		if !ok || len(s) > 10923 {
			return authorityFail("field_limit")
		}
		b, e := canonical(o)
		if e != nil {
			return e
		}
		var cert messageCertificate
		if e = json.Unmarshal(b, &cert); e != nil || validateMessageCertificate(cert) != nil {
			return authorityFail("certificate_invalid")
		}
		return nil
	})
}
func authorityMessagesRule() authorityRule {
	assoc := arObject(map[string]authorityRule{"binding": authorityMessageBindingRule(), "current": arNullable(arID), "pending": arNullable(arID)})
	tx := arWith(arObject(map[string]authorityRule{"id": arID, "kind": arEnum("issue", "renew"), "base_version": arN, "base_digest": arH, "previous_current": arNullable(arID), "intent": arBlob(stateBudget), "candidate": arNullable(arBlob(stateBudget)), "phase": arEnum("intent", "prepared", "issued", "published", "active", "aborted", "closed"), "resolution": arNullable(arBlob(stateBudget))}), func(o map[string]any) error {
		if (o["previous_current"] == nil) != (o["kind"] == "issue") {
			return authorityFail("message_phase")
		}
		if o["phase"] == "intent" && o["candidate"] != nil || o["phase"] != "intent" && o["phase"] != "aborted" && o["candidate"] == nil {
			return authorityFail("message_phase")
		}
		return nil
	})
	// Publication provider records retain the existing S2 exact wrapper and raw
	// owner-owned validation/witness bytes. Their authentication is a later slice.
	publication := arS2(reflect.TypeFor[messagePublication]())
	return arWith(arObject(map[string]authorityRule{"certificates": arArray(authorityCertificateRule(), 65536), "associations": arArray(assoc, 65536), "transactions": arArray(tx, 65536), "publications": arArray(publication, 65536)}), func(o map[string]any) error {
		for _, field := range []string{"certificates", "transactions", "publications"} {
			seen := map[string]bool{}
			for _, x := range o[field].([]any) {
				r := x.(map[string]any)
				k := "transaction"
				if field == "transactions" {
					k = "id"
				}
				id := r[k].(string)
				if seen[id] {
					return authorityFail("duplicate_message")
				}
				seen[id] = true
			}
		}
		seen := map[string]bool{}
		for _, x := range o["associations"].([]any) {
			b, _ := canonical(x.(map[string]any)["binding"])
			if seen[string(b)] {
				return authorityFail("duplicate_message")
			}
			seen[string(b)] = true
		}
		return nil
	})
}

func authorityBindingRule() authorityRule {
	return arWith(arS2(reflect.TypeFor[Binding]()), func(o map[string]any) error {
		for _, k := range []string{"path", "owner", "master_epoch", "registry_revision"} {
			if e := arText(o[k]); e != nil {
				return e
			}
		}
		if e := arToken(o["generation"]); e != nil {
			return e
		}
		if ValidatePath(o["path"].(string), "agent-identity") != "" {
			return authorityFail("field_format")
		}
		if e := arObject(map[string]authorityRule{"uid": arUID, "generation": arToken})(o["registrar_principal"]); e != nil {
			return e
		}
		if e := arUID(o["uid"]); e != nil {
			return e
		}
		if e := arN(o["registration_number"]); e != nil {
			return e
		}
		if e := arEnum("ephemeral", "persistent")(o["lifetime"]); e != nil {
			return e
		}
		return arEnum("active", "unbound", "revoked", "provisioned")(o["status"])
	})
}

func authorityIssuerRule() authorityRule {
	return arWith(arObject(map[string]authorityRule{"path": arText, "key": arKey, "master_epoch": arText, "registry_revision": arText, "lifetime_seconds": arInt(1, 86400)}), func(o map[string]any) error {
		if ValidatePath(o["path"].(string), "root-attestation") != "" {
			return authorityFail("field_format")
		}
		return nil
	})
}
func authorityIntentRule() authorityRule {
	return arObject(map[string]authorityRule{"binding": authorityBindingRule(), "issuer_policy": authorityIssuerRule(), "key_id": arKey, "issued_at": arStamp, "reserved_bytes": arInt(messageProofReserve, stateBudget), "base_version": arN, "base_digest": arH, "previous_current": arNullable(arID)})
}
func authorityCandidateRule() authorityRule {
	return arObject(map[string]authorityRule{"certificate": authorityCertificateRule(), "intent": arBlob(stateBudget), "effect": arObject(map[string]authorityRule{"binding": authorityMessageBindingRule(), "base_version": arN, "base_digest": arH, "current": arNullable(arID), "pending": arID, "phase": arEnum("issued"), "publication": arNullable(arBlob(stateBudget))})})
}
func authorityResolutionRule() authorityRule {
	return arObject(map[string]authorityRule{"outcome": arEnum("aborted", "issued"), "intent": arBlob(stateBudget), "candidate": arNullable(arBlob(stateBudget)), "version": arN, "digest": arH})
}
