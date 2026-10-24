//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"io"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"

	gj "github.com/relux-works/swarma-user-manager/tools/genjournal"
)

// This is local continuity evidence, not WC1 external restore authorization.
// Journal-first publication makes an interrupted rename fence on the next open.
type generationAnchor struct {
	Path  string   `json:"path"`
	Floor gj.Floor `json:"floor"`
}
type generationCommit struct {
	Anchor *generationAnchor
	Fenced bool
}

func validGenerationFloor(f gj.Floor) bool {
	return f.Seq >= 0 && f.Seq <= gj.MaxSeq && validDigest(f.Hash) && (f.Seq != 0 || f.Hash == gj.ZeroHash)
}

// Replay indexes only authenticated local lifecycle records. It never reconstructs
// a missing anchor file: that missing side of the commit is an operator incident.
func (j *Journal) observeGeneration(r AuditRecord) error {
	if r.Operation != "generation_anchor" && r.Operation != "generation_fence" {
		return nil
	}
	if r.Surface != "control" || r.Domain == nil || *r.Domain != "control" || r.Path == nil || *r.Path == "" {
		return failure("invalid generation commit")
	}
	if r.Operation == "generation_fence" {
		if r.RefusalCode == nil || *r.RefusalCode != "generation_source_fenced" || (r.Result != "refused" && r.Result != "unknown") || j.generation.Fenced {
			return failure("invalid generation fence")
		}
		j.generation.Fenced = true
		return nil
	}
	if j.generation.Fenced || r.RefusalCode != nil || (r.Result != "success" && r.Result != "unknown") || r.RequestID == nil || r.PayloadDigest == nil {
		return failure("invalid generation anchor")
	}
	seq, err := strconv.ParseInt(*r.RequestID, 10, 64)
	f := gj.Floor{Seq: seq, Hash: *r.PayloadDigest}
	if err != nil || strconv.FormatInt(seq, 10) != *r.RequestID || !validGenerationFloor(f) {
		return failure("invalid generation floor")
	}
	if old := j.generation.Anchor; old != nil && (old.Path != *r.Path || f.Seq < old.Floor.Seq || (f.Seq == old.Floor.Seq && f.Hash != old.Floor.Hash)) {
		return failure("generation commit discontinuity")
	}
	j.generation.Anchor = &generationAnchor{Path: *r.Path, Floor: f}
	return nil
}

func loadGenerationAnchor(s *Store, path string, initial gj.Floor) (generationAnchor, bool) {
	expected := s.journal.generation
	a := generationAnchor{Path: path, Floor: initial}
	if expected.Fenced {
		return a, true
	}
	// A leftover staged file is evidence of an interrupted update. Never clean it.
	var st unix.Stat_t
	if err := unix.Fstatat(int(s.dir.Fd()), "generation.next", &st, unix.AT_SYMLINK_NOFOLLOW); err != unix.ENOENT {
		return a, true
	}
	err := unix.Fstatat(int(s.dir.Fd()), "generation.anchor", &st, unix.AT_SYMLINK_NOFOLLOW)
	if err == unix.ENOENT {
		return a, expected.Anchor != nil || s.next != 1 || len(s.records) != 0 || !validGenerationFloor(initial)
	}
	if err != nil {
		return a, true
	}
	f, err := openRelative(s.dir, "generation.anchor", syscall.O_RDONLY, s.uid, 0600)
	if err != nil {
		return a, true
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	var stored generationAnchor
	if err != nil || len(raw) > 4096 || StrictJSON(bytes.NewReader(raw), &stored) != nil {
		return a, true
	}
	b, err := canonical(stored)
	if err != nil || !bytes.Equal(raw, b) || stored.Path != path || !validGenerationFloor(stored.Floor) || expected.Anchor == nil || stored != *expected.Anchor {
		return a, true
	}
	return stored, false
}

func persistGenerationAnchor(ctx context.Context, s *Store, a generationAnchor) Code {
	if auditContextExpired(ctx) {
		return "request_deadline_exceeded"
	}
	id, domain := strconv.FormatInt(a.Floor.Seq, 10), "control"
	r := AuditRecord{Surface: "control", Domain: &domain, Operation: "generation_anchor", RequestID: &id, PayloadDigest: &a.Floor.Hash, Path: &a.Path, Result: "success"}
	if c := s.journal.AppendContext(ctx, r); c != "" {
		return c
	}
	// Finish the local commit even if sync consumed the budget; the caller checks
	// the bounded context before any operation or transport effect.
	b, err := canonical(a)
	if err != nil {
		return "audit_unavailable"
	}
	f, err := openRelative(s.dir, "generation.next", syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL, s.uid, 0600)
	if err != nil {
		return "audit_unavailable"
	}
	n, err := f.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err != nil || ce != nil {
		return "audit_unavailable"
	}
	if syscall.Renameat(int(s.dir.Fd()), "generation.next", int(s.dir.Fd()), "generation.anchor") != nil || s.dir.Sync() != nil {
		return "audit_unavailable"
	}
	return ""
}
