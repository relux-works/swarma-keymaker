package keymaker

import "crypto/ed25519"

// custodyCause is local audit metadata, never a wire Code. The custody operation
// captures it under the Master lock; no later state read or global last-error
// slot can attribute a concurrent operation's failure to this request.
type custodyCause string

const (
	custodyClosed           custodyCause = "closed"
	custodyUnloaded         custodyCause = "unloaded"
	custodyProtectionFailed custodyCause = "protection_failed"
)

func (c custodyCause) valid() bool {
	return c == custodyClosed || c == custodyUnloaded || c == custodyProtectionFailed
}

func auditCustodyCause(code Code, cause custodyCause) *custodyCause {
	if code != "custody_unavailable" {
		return nil
	}
	return &cause
}

func validAuditCustody(r AuditRecord) bool {
	isCustody := r.RefusalCode != nil && *r.RefusalCode == "custody_unavailable"
	if r.CustodyCause == nil {
		return !isCustody
	}
	return isCustody && r.Result == "refused" && r.CustodyCause.valid()
}

// Production Masters supply detailed results internally without changing the
// existing public Signer contract. Other injected signers keep their own Codes;
// a custody refusal without a valid cause cannot be appended as new evidence.
type custodySigner interface {
	publicWithCause(string) ([]byte, Code, custodyCause)
	signWithCause(string, []byte) ([]byte, Code, custodyCause)
}

func publicForAudit(s Signer, path string) ([]byte, Code, custodyCause) {
	if detailed, ok := s.(custodySigner); ok {
		return detailed.publicWithCause(path)
	}
	public, code := s.Public(path)
	return public, code, ""
}
func signForAudit(s Signer, path string, data []byte) ([]byte, Code, custodyCause) {
	if detailed, ok := s.(custodySigner); ok {
		return detailed.signWithCause(path, data)
	}
	signature, code := s.Sign(path, data)
	return signature, code, ""
}
func (m *Master) publicWithCause(path string) ([]byte, Code, custodyCause) {
	return m.withPurposeCause(path, "agent-identity", func(k ed25519.PrivateKey) []byte { return append([]byte(nil), k[32:]...) })
}
func (m *Master) signWithCause(path string, data []byte) ([]byte, Code, custodyCause) {
	return m.withPurposeCause(path, "agent-identity", func(k ed25519.PrivateKey) []byte { return ed25519.Sign(k, data) })
}
