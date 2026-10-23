package keymaker

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// canonical encodes the CCJ-1 subset used by typed audit records. It does not
// inherit encoding/json's HTML or U+2028 escaping and rejects noninteger numbers.
func canonical(v any) ([]byte, error) {
	raw, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value any
	if e = d.Decode(&value); e != nil {
		return nil, e
	}
	var out bytes.Buffer
	var emit func(any) error
	quote := func(s string) {
		out.WriteByte('"')
		for _, r := range s {
			switch r {
			case '"', '\\':
				out.WriteByte('\\')
				out.WriteRune(r)
			case '\b':
				out.WriteString(`\b`)
			case '\t':
				out.WriteString(`\t`)
			case '\n':
				out.WriteString(`\n`)
			case '\f':
				out.WriteString(`\f`)
			case '\r':
				out.WriteString(`\r`)
			default:
				if r < 32 {
					fmt.Fprintf(&out, `\u%04x`, r)
				} else {
					out.WriteRune(r)
				}
			}
		}
		out.WriteByte('"')
	}
	emit = func(v any) error {
		switch x := v.(type) {
		case nil:
			out.WriteString("null")
		case bool:
			if x {
				out.WriteString("true")
			} else {
				out.WriteString("false")
			}
		case string:
			quote(x)
		case json.Number:
			n, e := strconv.ParseInt(string(x), 10, 64)
			if e != nil || n > 9007199254740991 || n < -9007199254740991 {
				return failure("invalid audit number")
			}
			out.WriteString(strconv.FormatInt(n, 10))
		case []any:
			out.WriteByte('[')
			for i, v := range x {
				if i > 0 {
					out.WriteByte(',')
				}
				if e := emit(v); e != nil {
					return e
				}
			}
			out.WriteByte(']')
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			out.WriteByte('{')
			for i, k := range keys {
				if i > 0 {
					out.WriteByte(',')
				}
				quote(k)
				out.WriteByte(':')
				if e := emit(x[k]); e != nil {
					return e
				}
			}
			out.WriteByte('}')
		default:
			return failure("invalid audit value")
		}
		return nil
	}
	if e = emit(value); e != nil {
		return nil, e
	}
	return out.Bytes(), nil
}

type AuditRecord struct {
	Seq           uint64  `json:"seq"`
	Time          *string `json:"time"`
	Instance      string  `json:"instance"`
	Surface       string  `json:"surface"`
	RequestID     *string `json:"request_id"`
	PeerUID       *uint32 `json:"peer_uid"`
	Generation    *string `json:"generation"`
	Path          *string `json:"path"`
	Epoch         *string `json:"master_epoch"`
	Operation     string  `json:"operation"`
	Domain        *string `json:"domain"`
	PayloadDigest *string `json:"payload_digest"`
	Result        string  `json:"result"`
	RefusalCode   *Code   `json:"refusal_code"`
	Previous      string  `json:"previous_digest"`
	Digest        string  `json:"record_digest"`
}
type Auditor interface{ Append(AuditRecord) Code }

// AuditClock reports whether UTC is trustworthy. Uncertain time is recorded as
// null/unknown rather than inventing a timestamp for the operation.
type AuditClock interface{ UTC() (time.Time, bool) }
type systemAuditClock struct{}

func (systemAuditClock) UTC() (time.Time, bool) { return time.Now().UTC(), true }

type durableFile interface {
	io.Writer
	Sync() error
}
type auditSeal struct {
	First  uint64 `json:"first_seq"`
	Last   uint64 `json:"last_seq"`
	Digest string `json:"last_digest"`
}
type Journal struct {
	mu           sync.Mutex
	dir          *os.File
	file         *os.File
	writer       durableFile
	uid          uint32
	instance     string
	seq          uint64
	previous     string
	first        uint64
	segment      uint64
	size         int64
	total        int64
	failed       bool
	segmentLimit int64
	totalLimit   int64
	reserve      int64
	clock        AuditClock
	binding      bindingCommit
}

func auditDigest(r AuditRecord) (string, error) {
	b, e := canonical(r)
	if e != nil {
		return "", e
	}
	var obj map[string]any
	if json.Unmarshal(b, &obj) != nil {
		return "", failure("invalid audit record")
	}
	delete(obj, "record_digest")
	b, e = canonical(obj)
	if e != nil {
		return "", e
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
func auditName(n uint64) string { return fmt.Sprintf("%016d.jsonl", n) }
func OpenJournal(dir *os.File, uid uint32) (*Journal, error) {
	return openJournal(dir, uid, systemAuditClock{}, rand.Reader)
}
func openJournal(dir *os.File, uid uint32, clock AuditClock, entropy io.Reader) (*Journal, error) {
	return openJournalChecked(dir, uid, clock, entropy, nil)
}

// The callback runs after read-only replay and before opening/creating a writer.
func openJournalChecked(dir *os.File, uid uint32, clock AuditClock, entropy io.Reader, check func(*Journal) error) (*Journal, error) {
	j := &Journal{dir: dir, uid: uid, segment: 1, first: 1, segmentLimit: 64 << 20, totalLimit: (1 << 30) + (16 << 20), reserve: 16 << 20, clock: clock}
	var nonce [16]byte
	if _, e := io.ReadFull(entropy, nonce[:]); e != nil {
		return nil, failure("audit instance unavailable")
	}
	j.instance = hex.EncodeToString(nonce[:])
	// A retained directory fd is opened independently for enumeration; never rewind
	// a shared descriptor or follow a swapped filesystem path.
	fd, e := syscall.Openat(int(dir.Fd()), ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, failure("audit directory unavailable")
	}
	listing := os.NewFile(uintptr(fd), "audit")
	entries, e := listing.ReadDir(-1)
	listing.Close()
	if e != nil {
		return nil, failure("audit directory unavailable")
	}
	names := map[string]bool{}
	var segments []string
	for _, entry := range entries {
		n := entry.Name()
		names[n] = true
		if strings.HasSuffix(n, ".jsonl") {
			segments = append(segments, n)
		} else if !strings.HasSuffix(n, ".jsonl.seal") {
			return nil, failure("unexpected audit evidence")
		}
	}
	sort.Strings(segments)
	for i, n := range segments {
		if n != auditName(uint64(i+1)) {
			return nil, failure("audit sequence discontinuity")
		}
		f, e := openRelative(dir, n, syscall.O_RDONLY, uid, 0600)
		if e != nil {
			return nil, e
		}
		data, e := io.ReadAll(io.LimitReader(f, j.segmentLimit+1))
		f.Close()
		if e != nil || int64(len(data)) > j.segmentLimit {
			return nil, failure("audit segment unavailable")
		}
		j.total += int64(len(data))
		if j.total > j.totalLimit {
			return nil, failure("audit budget exceeded")
		}
		if len(data) > 0 && data[len(data)-1] != '\n' {
			return nil, failure("incomplete audit record")
		}
		first := j.seq + 1
		lines := bytes.Split(data, []byte{'\n'})
		for _, line := range lines[:len(lines)-1] {
			if len(line) == 0 {
				return nil, failure("empty audit record")
			}
			if len(line) > 8192 {
				return nil, failure("audit record too large")
			}
			var r AuditRecord
			if StrictJSON(bytes.NewReader(line), &r) != nil {
				return nil, failure("invalid audit record")
			}
			b, e := canonical(r)
			digest, e2 := auditDigest(r)
			if e != nil || e2 != nil || !bytes.Equal(b, line) || r.Seq != j.seq+1 || r.Previous != j.previous || r.Digest != digest {
				return nil, failure("audit continuity failure")
			}
			if err := j.observeBinding(r); err != nil {
				return nil, err
			}
			j.seq = r.Seq
			j.previous = r.Digest
		}
		sealName := n + ".seal"
		sealed := names[sealName]
		if sealed {
			f, e := openRelative(dir, sealName, syscall.O_RDONLY, uid, 0600)
			if e != nil {
				return nil, e
			}
			var seal auditSeal
			e = StrictJSON(f, &seal)
			f.Close()
			if e != nil || seal.First != first || seal.Last != j.seq || seal.Digest != j.previous {
				return nil, failure("invalid audit seal")
			}
			delete(names, sealName)
		} else if i != len(segments)-1 {
			return nil, failure("unsealed historical segment")
		}
		delete(names, n)
		j.segment = uint64(i + 1)
		j.first = first
		j.size = int64(len(data))
		if i == len(segments)-1 && sealed {
			j.segment++
			j.first = j.seq + 1
			j.size = 0
		}
	}
	if len(names) != 0 {
		return nil, failure("orphan audit seal")
	}
	if check != nil {
		if err := check(j); err != nil {
			return nil, err
		}
	}
	flags := syscall.O_WRONLY | syscall.O_APPEND
	if len(segments) == 0 || j.segment > uint64(len(segments)) {
		flags |= syscall.O_CREAT | syscall.O_EXCL
	}
	j.file, e = openRelative(dir, auditName(j.segment), flags, uid, 0600)
	if e != nil {
		return nil, e
	}
	j.writer = j.file
	if dir.Sync() != nil {
		j.file.Close()
		return nil, failure("audit directory sync failed")
	}
	return j, nil
}
func (j *Journal) rotate() error {
	seal := auditSeal{j.first, j.seq, j.previous}
	b, e := canonical(seal)
	if e != nil {
		return e
	}
	f, e := openRelative(j.dir, auditName(j.segment)+".seal", syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL, j.uid, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return failure("audit seal failed")
	}
	if j.dir.Sync() != nil {
		return failure("audit seal sync failed")
	}
	if e = j.file.Close(); e != nil {
		return e
	}
	j.segment++
	j.first = j.seq + 1
	j.size = 0
	j.file, e = openRelative(j.dir, auditName(j.segment), syscall.O_WRONLY|syscall.O_APPEND|syscall.O_CREAT|syscall.O_EXCL, j.uid, 0600)
	if e != nil {
		return e
	}
	j.writer = j.file
	return j.dir.Sync()
}
func (j *Journal) Append(r AuditRecord) Code {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.appendLocked(r)
}
func (j *Journal) appendLocked(r AuditRecord) Code {
	if j.failed {
		return "audit_unavailable"
	}
	r.Seq = j.seq + 1
	r.Instance = j.instance
	r.Previous = j.previous
	instant, trusted := j.clock.UTC()
	if trusted && instant.Year() >= 1970 && instant.Year() <= 9999 {
		now := instant.UTC().Format("2006-01-02T15:04:05Z")
		r.Time = &now
	} else {
		r.Time = nil
		r.Result = "unknown"
	}
	digest, e := auditDigest(r)
	if e != nil {
		j.failed = true
		return "audit_unavailable"
	}
	r.Digest = digest
	b, e := canonical(r)
	b = append(b, '\n')
	if e != nil || len(b) > 8192 {
		j.failed = true
		return "audit_unavailable"
	}
	budget := j.totalLimit - j.reserve
	if r.RefusalCode != nil || r.Result == "refused" {
		budget = j.totalLimit
	}
	if j.total+int64(len(b)) > budget {
		j.failed = true
		return "audit_unavailable"
	}
	if j.size+int64(len(b)) > j.segmentLimit {
		if j.rotate() != nil {
			j.failed = true
			return "audit_unavailable"
		}
	}
	n, e := j.writer.Write(b)
	if e != nil || n != len(b) {
		j.failed = true
		return "audit_unavailable"
	}
	if j.writer.Sync() != nil {
		j.failed = true
		return "audit_unavailable"
	}
	if j.observeBinding(r) != nil {
		j.failed = true
		return "audit_unavailable"
	}
	j.seq = r.Seq
	j.previous = r.Digest
	j.size += int64(len(b))
	j.total += int64(len(b))
	return ""
}
func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.failed = true
	return j.file.Close()
}
