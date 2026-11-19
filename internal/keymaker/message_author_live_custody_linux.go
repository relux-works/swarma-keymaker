//go:build linux

package keymaker

import (
	"golang.org/x/sys/unix"
	"syscall"
)

// protectMALiveMemory only moves an already selected independent root into a
// dump-excluded mapping. It reads no file, creates no seed and provisions no
// role or issuer. Production has no root loader in this slice. Test fixtures
// call this with their historical public seed; mlock remains best effort.
func protectMALiveMemory(k *messageAuthorKey) Code {
	if k == nil {
		return "custody_unavailable"
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed || k.mapped || len(k.seed) != 32 || k.role != messageAuthorRole || !validJ7Instance(k.instance) {
		return "custody_unavailable"
	}
	page, e := syscall.Mmap(-1, 0, 4096, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if e != nil {
		return "custody_unavailable"
	}
	if unix.Madvise(page, unix.MADV_DONTDUMP) != nil {
		erase(page)
		syscall.Munmap(page)
		return "custody_unavailable"
	}
	locked := syscall.Mlock(page) == nil
	copy(page, k.seed)
	erase(k.seed)
	k.seed = page[:32]
	k.mapped = true
	k.locked = locked
	return ""
}
func eraseMALiveMemory(seed []byte, mapped, locked bool) error {
	if !mapped {
		erase(seed)
		return nil
	}
	page := seed[:4096]
	erase(page)
	if locked {
		_ = syscall.Munlock(page)
	}
	return syscall.Munmap(page)
}
