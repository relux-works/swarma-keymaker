//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"

	"github.com/relux-works/swarma-keymaker/internal/timeconfidence"
)

// RunMessageAuthorOperator is a stopped local operator boundary. It reads no
// caller-selected seed and supplies no network method. Only issuer-seed-init
// creates independent issuer custody; issuer-pin reads it for public output.
// Enrollment input is the exact closed
// Binding JSON, including the operator-asserted purpose-1 epoch/registration.
// The caller owns process hardening and supplies an explicit command/config.
func RunMessageAuthorOperator(ctx context.Context, command, path string, number uint64, input io.Reader, out io.Writer) Code {
	return runMessageAuthorOperator(ctx, command, path, number, input, out, productionMALiveDeps())
}

func runMessageAuthorOperator(ctx context.Context, command, path string, number uint64, input io.Reader, out io.Writer, d maLiveServiceDeps) Code {
	if command != "init" && command != "enroll" && command != "retire" && command != "issuer-seed-init" && command != "issuer-pin" || command != "retire" && number != 0 || command == "retire" && number == 0 {
		return "request_malformed"
	}
	var cfg Config
	if d.config == nil || d.config(path, &cfg) != nil || cfg.maLive == nil {
		return "role_not_permitted"
	}
	m := cfg.maLive
	uid := uint32(os.Getuid())
	if uid == 0 || m.UID != uid || uint32(os.Geteuid()) != uid || m.GID != uint32(os.Getgid()) || uint32(os.Getegid()) != m.GID {
		return "role_not_permitted"
	}
	if command == "issuer-pin" {
		if out == nil || safeAncestors(m.State.Path, uid) != nil {
			return "request_malformed"
		}
		dir, e := OpenDirectory(m.State.Path, uid, 0700)
		if e != nil {
			return "custody_unavailable"
		}
		defer dir.Close()
		if !j7NoACL(int(dir.Fd()), true) {
			return "custody_unavailable"
		}
		k, c := loadMAIssuerKey(dir, uid)
		if c != "" {
			return c
		}
		defer k.close()
		raw, c := k.pin()
		if c != "" {
			return c
		}
		if _, e = out.Write(raw); e != nil {
			return "custody_unavailable"
		}
		return ""
	}
	if m.Generation == nil {
		return "generation_source_unavailable"
	}
	clock, e := d.clock(m.Time)
	if e != nil || clock == nil || timeconfidence.Start(ctx, clock) != nil {
		return "clock_untrusted"
	}
	if safeAncestors(m.State.Path, uid) != nil {
		return "message_author_unqualified"
	}
	dir, e := OpenDirectory(m.State.Path, uid, 0700)
	if e != nil {
		return "message_author_unqualified"
	}
	defer dir.Close()
	if !j7NoACL(int(dir.Fd()), true) {
		return "message_author_unqualified"
	}
	lock, e := LockState(dir, uid)
	if e != nil {
		return "message_author_unqualified"
	}
	defer lock.Close()
	var s *Store
	var c Code
	if command == "init" {
		s, c = initMALive(ctx, dir, uid, systemAuditClock{provider: clock}, m.Instance, m.Epoch, m.Registry)
	} else {
		expected, e := d.head(m.State.Head)
		if e != nil {
			return "message_author_unqualified"
		}
		s, c = openMALive(dir, uid, systemAuditClock{provider: clock}, expected)
	}
	if c != "" {
		return c
	}
	defer s.Close()
	if s.maLive.Instance != m.Instance || s.maLive.Epoch != m.Epoch || s.maLive.Registry != m.Registry || s.maLive.Fenced {
		return "message_author_unqualified"
	}
	generation := d.generation(s, *m.Generation)
	c = generation.WithActive(ctx, m.Operator.UID, m.Operator.Generation, func(ctx context.Context) Code {
		switch command {
		case "init":
			return ""
		case "enroll":
			if input == nil {
				return "request_malformed"
			}
			raw, e := io.ReadAll(io.LimitReader(input, 8193))
			if e != nil || len(raw) > 8192 {
				return "request_malformed"
			}
			var b Binding
			if StrictJSON(bytes.NewReader(raw), &b) != nil {
				return "request_malformed"
			}
			return s.enrollMALive(ctx, m.Operator, b)
		case "issuer-seed-init":
			return s.initMAIssuerSeed(ctx, m.Operator, nil)
		case "retire":
			return s.retireMALive(ctx, m.Operator, number)
		}
		return "request_malformed"
	})
	if c != "" {
		return c
	}
	digest, e := s.contentDigest(s.version)
	if e != nil {
		return "message_author_unqualified"
	}
	// The reported head does not install or advance the root-owned pin.
	if out == nil {
		return "request_malformed"
	}
	if e = json.NewEncoder(out).Encode(j7HeadPin{Version: s.version, Digest: digest}); e != nil {
		return "message_author_unqualified"
	}
	return ""
}
