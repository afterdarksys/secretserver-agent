//go:build linux

package securemem

import (
	"github.com/awnumar/memguard"
	"golang.org/x/sys/unix"
)

// MemGuard's memcall treats MADV_DONTDUMP as best effort. Keep our stricter
// contract: do not expose a plaintext view if dump exclusion cannot be applied.
func harden(b *memguard.LockedBuffer) error {
	if unix.Madvise(b.Inner(), unix.MADV_DONTDUMP) != nil {
		return ErrUnavailable
	}
	return nil
}
