package keymaker

import (
	"bytes"
	"encoding/binary"
	"io"
)

const MaxFrame = 65536

func SSHString(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}
func PublicBlob(public []byte) []byte {
	return append(SSHString([]byte("ssh-ed25519")), SSHString(public)...)
}
func Packet(body []byte) []byte { return SSHString(body) }

var AgentFailure = Packet([]byte{5})

func ReadFrame(r io.Reader) ([]byte, Code) {
	var head [4]byte
	n, e := io.ReadFull(r, head[:])
	if e != nil {
		if n == 0 && e == io.EOF {
			return nil, ""
		}
		return nil, "frame_truncated"
	}
	size := binary.BigEndian.Uint32(head[:])
	if size == 0 {
		return nil, "frame_malformed"
	}
	if size > MaxFrame {
		return nil, "frame_too_large"
	}
	b := make([]byte, size)
	if _, e = io.ReadFull(r, b); e != nil {
		return nil, "frame_truncated"
	}
	return b, ""
}

type wireReader struct {
	b   []byte
	bad bool
}

func (r *wireReader) string() []byte {
	if len(r.b) < 4 {
		r.bad = true
		return nil
	}
	n := binary.BigEndian.Uint32(r.b[:4])
	r.b = r.b[4:]
	if uint64(n) > uint64(len(r.b)) {
		r.bad = true
		return nil
	}
	v := r.b[:int(n)]
	r.b = r.b[int(n):]
	return v
}
func (r *wireReader) u32() uint32 {
	if len(r.b) < 4 {
		r.bad = true
		return 0
	}
	n := binary.BigEndian.Uint32(r.b[:4])
	r.b = r.b[4:]
	return n
}

type agentRequest struct {
	operation string
	key, data []byte
	namespace string
	flags     uint32
}

func parseAgent(body []byte) (agentRequest, Code) {
	var q agentRequest
	if len(body) == 0 {
		return q, "frame_malformed"
	}
	switch body[0] {
	case 11:
		q.operation = "pubkey"
		if len(body) != 1 {
			return q, "frame_malformed"
		}
	case 13:
		q.operation = "sign"
		r := wireReader{b: body[1:]}
		q.key = r.string()
		q.data = r.string()
		q.flags = r.u32()
		if r.bad || len(r.b) != 0 {
			return q, "frame_malformed"
		}
	default:
		q.operation = "unsupported"
		return q, "agent_message_unsupported"
	}
	return q, ""
}
func validatePreimage(data []byte) (string, Code) {
	if !bytes.HasPrefix(data, []byte("SSHSIG")) {
		return "", "sign_data_not_sshsig"
	}
	r := wireReader{b: data[6:]}
	namespace := r.string()
	reserved := r.string()
	hash := r.string()
	digest := r.string()
	if r.bad || len(r.b) != 0 || len(reserved) != 0 || !(string(hash) == "sha256" && len(digest) == 32 || string(hash) == "sha512" && len(digest) == 64) {
		return "", "sshsig_malformed"
	}
	if string(namespace) != "git" {
		return "", "namespace_not_permitted"
	}
	return "git", ""
}
