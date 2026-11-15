package keymaker

import (
	"bytes"
	"context"
	"os"
	"reflect"
	"strconv"

	"github.com/relux-works/swarma-keymaker/internal/control"
)

const j7SigningSchema = 5

func j7StateSchema(schema int) bool { return schema == j7Schema || schema == j7SigningSchema }
func j7SigningMethod(method string) bool {
	return method == "j7_sign" || method == "j7_pubkey" || method == "j7_enroll"
}

// Schema 5 adds a required participant. Schema 4's closed participant is kept
// byte-for-byte; old readers must refuse the new outer schema, not drop history.
type j7SigningInventory struct {
	Format      string            `json:"format"`
	Records     []j7SigningRecord `json:"records"`
	Enrollments []j7Enrollment    `json:"enrollments"`
}
type j7SigningRecord struct {
	Caller     Principal           `json:"caller"`
	ID         string              `json:"request_id"`
	Run        string              `json:"run_id"`
	Binding    Binding             `json:"binding"`
	Origin     j7Origin            `json:"origin"`
	Method     string              `json:"method"`
	Operation  string              `json:"operation"`
	InputHash  string              `json:"input_sha256"`
	ResultHash string              `json:"result_sha256"`
	Grants     []string            `json:"grants"`
	Consent    j7ConsentPermission `json:"consent"`
	EventID    string              `json:"event_id"`
	Release    string              `json:"release"`
}
type j7Enrollment struct {
	Origin            j7OriginKey         `json:"origin"`
	Identity          uint64              `json:"identity_registration_number"`
	Grant             string              `json:"grant_id"`
	ConsentID         string              `json:"consent_event_id"`
	ConsentResultHash string              `json:"consent_result_sha256"`
	Consent           j7ConsentPermission `json:"consent"`
}

func (j *j7SigningInventory) UnmarshalJSON(raw []byte) error {
	if e := messageRequired(raw, reflect.TypeFor[j7SigningInventory]()); e != nil {
		return e
	}
	type plain j7SigningInventory
	return StrictJSON(bytes.NewReader(raw), (*plain)(j))
}
func cloneJ7Signing(j *j7SigningInventory) *j7SigningInventory {
	if j == nil {
		return nil
	}
	c := *j
	c.Records = append([]j7SigningRecord{}, j.Records...)
	for i := range c.Records {
		c.Records[i].Grants = append([]string{}, j.Records[i].Grants...)
	}
	c.Enrollments = append([]j7Enrollment{}, j.Enrollments...)
	return &c
}
func (s *Store) j7SigningRecord(p Principal, id string) *j7SigningRecord {
	if s.j7Signing != nil {
		for i := range s.j7Signing.Records {
			r := &s.j7Signing.Records[i]
			if r.Caller == p && r.ID == id {
				return r
			}
		}
	}
	return nil
}
func (s *Store) j7UnknownHandoff() bool {
	if s.j7Signing != nil {
		for _, r := range s.j7Signing.Records {
			if r.Release == "handoff_unknown" {
				return true
			}
		}
	}
	return false
}
func (s *Store) validateJ7Signing() error {
	j := s.j7Signing
	if s.schema != j7SigningSchema {
		if j != nil {
			return failure("unexpected signing participant")
		}
		return nil
	}
	if j == nil || j.Format != "keymaker-j7-signing-state/1" || j.Records == nil || j.Enrollments == nil || len(j.Records) > j7HistoryLimit || len(j.Enrollments) > j7HistoryLimit {
		return failure("invalid signing participant")
	}
	seen := map[requestKey]bool{}
	for _, r := range j.Records {
		key := requestKey{r.Caller, r.ID}
		if seen[key] || !messageID(r.ID) || !messageID(r.Run) || !r.Origin.valid() || !j7SigningMethod(r.Method) || !validDigest(r.InputHash) || !validDigest(r.ResultHash) || r.Grants == nil || r.Release != "prepared" && r.Release != "handoff_unknown" && r.Release != "released" {
			return failure("invalid signing record")
		}
		seen[key] = true
		run := false
		for _, v := range s.j7.Runs {
			if v.ID == r.Run && v.Binding == r.Binding && v.Origin == r.Origin && v.Launcher == r.Caller {
				run = true
			}
		}
		if !run {
			return failure("foreign signing run")
		}
		index, ok := s.requestIndex[key]
		if !ok {
			return failure("lost signing result")
		}
		prior := s.requests[index]
		if prior.Method != r.Method || prior.Status != "committed" || j7Hash([]byte(prior.Arguments)) != r.InputHash || j7Hash(prior.Result) != r.ResultHash {
			return failure("changed signing result")
		}

		params, err := control.Decode([]byte(prior.Arguments))
		if err != nil {
			return failure("invalid signing input")
		}
		plan, code := j7ParseRequest(control.Request{Method: r.Method, Params: params})
		if code != "" || plan.operation != r.Operation {
			return failure("invalid retained operation")
		}
		obj, err := control.Decode(prior.Result)
		if err != nil {
			return failure("invalid retained signing result")
		}
		if plan.grant != nil {
			if len(r.Grants) != 1 || r.Grants[0] != plan.grant.ID() {
				return failure("changed grant authority")
			}
		} else if len(r.Grants) != 0 {
			return failure("unexpected grant authority")
		}
		switch r.Method {
		case "j7_pubkey":
			if len(obj) != 2 || obj["profile"] != "j7-request-public/1" || r.EventID != "" {
				return failure("invalid retained public key")
			}
			pub, ok := obj["public_key"].(string)
			if !ok || !j7Public(pub) {
				return failure("invalid retained public key")
			}
		case "j7_enroll":
			if len(obj) != 1 || obj["grant_id"] != plan.grant.ID() || r.EventID != "" {
				return failure("invalid retained enrollment")
			}
		case "j7_sign":
			encoded, ok := obj["signed_object_b64"].(string)
			if !ok || len(obj) != 4 {
				return failure("invalid retained signature")
			}
			raw, c := j7Decode64(encoded, 16384)
			if c != "" {
				return failure("invalid retained signature")
			}
			event, ok := j7ValidateEvent(raw)
			if !ok || event.ID != r.EventID || obj["public_key"] != event.Pubkey || obj["object_id"] != event.ID || event.Pubkey != plan.contract.Grantee || event.CreatedAt >= plan.contract.NotAfter {
				return failure("changed retained signature")
			}
			if r.Operation == "consent_v3" {
				if event.Kind != 8181 || obj["profile"] != "swarma-rental-consent-v1" || event.Tags[1][1] != plan.consent.Contract || event.Tags[2][1] != plan.consent.Booking || event.Tags[3][1] != plan.consent.Privacy || r.Consent.Contract != plan.consent.Contract || r.Consent.Booking != plan.consent.Booking || r.Consent.Privacy != plan.consent.Privacy {
					return failure("changed retained consent")
				}
			}
			if r.Operation == "envelope_v3" {
				v := plan.envelope
				if event.Kind != 8185 || obj["profile"] != "swarma-instruction-v1/draft" || event.CreatedAt < plan.contract.NotBefore || event.Tags[1][1] != v.To || event.Tags[2][1] != plan.grant.ID() || event.Tags[3][1] != v.Action || event.Tags[4][1] != j7Hash(plan.instruction) || event.Tags[5][1] != v.Room || event.Tags[6][1] != v.MXID {
					return failure("changed retained envelope")
				}
				if v.Action == "land" && event.Tags[8][1] != v.Repo || v.Action == "spend" && event.Tags[8][1] != strconv.FormatInt(v.Amount, 10) {
					return failure("changed retained action terms")
				}
			}
		}
		for _, id := range r.Grants {
			if !validDigest(id) {
				return failure("invalid signing authority")
			}
		}
		if r.Method == "j7_sign" && (!validDigest(r.EventID) || r.Operation != "consent_v3" && r.Operation != "envelope_v3") {
			return failure("invalid signed profile")
		}
		if r.Operation == "consent_v3" && (!validDigest(r.Consent.Contract) || !validDigest(r.Consent.Booking) || !validDigest(r.Consent.Privacy)) {
			return failure("lost consent terms")
		}
	}
	enrolled := map[struct {
		Origin j7OriginKey
		Grant  string
	}]bool{}
	for _, e := range j.Enrollments {
		key := struct {
			Origin j7OriginKey
			Grant  string
		}{e.Origin, e.Grant}
		if enrolled[key] || !e.Origin.valid() || e.Identity != s.j7.Identity || !validDigest(e.Grant) || !validDigest(e.ConsentID) || !validDigest(e.ConsentResultHash) || !e.Consent.AndUse {
			return failure("invalid enrollment")
		}
		enrolled[key] = true
		match := false
		for _, r := range j.Records {
			if r.Operation == "consent_v3" && r.EventID == e.ConsentID && r.ResultHash == e.ConsentResultHash && r.Origin.key() == e.Origin && r.Consent == e.Consent && r.Binding.Number == e.Identity && r.Release == "released" {
				match = true
			}
		}
		if !match {
			return failure("unreleased enrollment")
		}
	}
	return nil
}
func openJ7SigningStore(dir *os.File, uid uint32, clock AuditClock, expected j7Expectation) (*Store, error) {
	s, _, _, e := openCustodyStateMessage(dir, uid, clock, j7SigningSchema, false, expected)
	if e != nil {
		return nil, e
	}
	if !s.j7HeadMatches(expected) || s.j7UnknownHandoff() {
		s.Close()
		return nil, failure("J7 signing continuity unavailable")
	}
	return s, nil
}

// migrateJ7Signing is a stopped-operator action, never a native route. Its
// independently retained head is not inferred from the current local snapshot.
func (s *Store) migrateJ7Signing(ctx context.Context, expected j7Expectation) Code {
	if !s.mu.LockContext(ctx) {
		return "request_deadline_exceeded"
	}
	defer s.mu.Unlock()
	if s.failed || s.schema != j7Schema || s.j7 == nil || s.j7Signing != nil || s.validateJ7() != nil || !s.j7HeadMatches(expected) {
		return "j7_state_fenced"
	}
	s.schema = j7SigningSchema
	s.j7Signing = &j7SigningInventory{Format: "keymaker-j7-signing-state/1", Records: []j7SigningRecord{}, Enrollments: []j7Enrollment{}}
	return s.commitJ7(ctx)
}
func (s *Store) j7Enrolled(origin j7OriginKey, identity uint64, id string) bool {
	if s.j7Signing != nil {
		for _, e := range s.j7Signing.Enrollments {
			if e.Origin == origin && e.Identity == identity && e.Grant == id {
				return true
			}
		}
	}
	return false
}
