// Package securemem owns guarded, locked plaintext buffers. It deliberately does
// not use MemGuard's encrypted Enclave API. No heap fallback is permitted.
// MemGuard attempts to disable core dumps; operators must also enforce core=0.
package securemem

import (
	"errors"
	"fmt"
	"github.com/awnumar/memguard"
	"sync"
)

var ErrDestroyed = errors.New("secure memory buffer has been destroyed")
var ErrUnavailable = errors.New("protected memory unavailable")

const MaxSecretSize = 1 << 20

// All memory operations and borrowed views share one lock because MemGuard may
// purge every allocation on failure. Never call MemGuard directly alongside
// this adapter, or reenter this package from a WithBytes callback.
var sessionMu sync.Mutex
var failed bool

// Buffer owns read-only locked plaintext until explicitly destroyed. It cannot
// erase copies made by callers or downstream cryptographic/network libraries.
type Buffer struct {
	memory *memguard.LockedBuffer
	size   int
}

func protected(fn func() error) (err error) {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	defer func() {
		if recover() != nil {
			failed = true
			err = ErrUnavailable
		}
	}()
	return fn()
}

func allocate(size int, init func(*memguard.LockedBuffer)) (*Buffer, error) {
	if size < 1 || size > MaxSecretSize {
		return nil, fmt.Errorf("secret size must be 1–%d bytes", MaxSecretSize)
	}
	var b *Buffer
	err := protected(func() error {
		// A dependency panic can leave a partially allocated mapping. Poison the
		// adapter until process restart so retries cannot accumulate leaked mappings.
		if failed {
			return ErrUnavailable
		}
		p := memguard.NewBuffer(size)
		keep := false
		defer func() {
			if !keep {
				p.Destroy()
			}
		}()
		if p.Size() != size {
			return ErrUnavailable
		}
		if err := harden(p); err != nil {
			return err
		}
		if init != nil {
			init(p)
		}
		p.Freeze()
		b = &Buffer{memory: p, size: size}
		keep = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	return b, nil
}
func New(size int) (*Buffer, error) { return allocate(size, nil) }

// Consume transfers ownership and wipes src on success and failure. Previous
// immutable strings and copies of src remain outside this ownership contract.
func Consume(src []byte) (*Buffer, error) {
	defer memguard.WipeBytes(src)
	return allocate(len(src), func(p *memguard.LockedBuffer) { p.Copy(src) })
}
func Random(size int) (*Buffer, error) {
	return allocate(size, func(p *memguard.LockedBuffer) { p.Scramble() })
}
func (b *Buffer) valid() error {
	if failed {
		return ErrUnavailable
	}
	if b.memory == nil || !b.memory.IsAlive() {
		return ErrDestroyed
	}
	return nil
}
func (b *Buffer) Len() int {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	if b.valid() != nil {
		return 0
	}
	return b.size
}
func (b *Buffer) String() string   { return "[protected secret]" }
func (b *Buffer) GoString() string { return "[protected secret]" }
func (b *Buffer) MarshalJSON() ([]byte, error) {
	return nil, errors.New("protected secrets cannot be serialized")
}
func (b *Buffer) WriteAt(src []byte, offset int) (int, error) {
	err := protected(func() error {
		if err := b.valid(); err != nil {
			return err
		}
		if offset < 0 || offset > b.size || len(src) > b.size-offset {
			return errors.New("secure memory write out of bounds")
		}
		b.memory.Melt()
		defer b.memory.Freeze()
		b.memory.CopyAt(offset, src)
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(src), nil
}

// WithBytes borrows an immutable locked view. Do not retain, mutate, convert to
// string, or reenter this adapter from the callback. Keep callbacks short: all
// adapter operations are serialized. Callback panics return a redacted error.
func (b *Buffer) WithBytes(fn func([]byte) error) error {
	if fn == nil {
		return errors.New("secure memory callback is nil")
	}
	return protected(func() error {
		if err := b.valid(); err != nil {
			return err
		}
		return invoke(fn, b.memory.Bytes())
	})
}
func invoke(fn func([]byte) error, p []byte) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrUnavailable
		}
	}()
	return fn(p)
}

// CopyTo copies directly between locked buffers without allocating a snapshot.
func (b *Buffer) CopyTo(dst *Buffer) error {
	if dst == nil || b == dst {
		return errors.New("invalid secure memory destination")
	}
	return protected(func() error {
		if err := b.valid(); err != nil {
			return err
		}
		if err := dst.valid(); err != nil {
			return err
		}
		if b.size != dst.size {
			return errors.New("secure memory size mismatch")
		}
		dst.memory.Melt()
		defer dst.memory.Freeze()
		dst.memory.Copy(b.memory.Bytes())
		return nil
	})
}

// Destroy wipes and frees owned memory. It is idempotent, including after purge.
func (b *Buffer) Destroy() error {
	return protected(func() error {
		if b.memory != nil {
			b.memory.Destroy()
			b.memory = nil
		}
		b.size = 0
		return nil
	})
}

// Purge invalidates all adapter buffers. Only executables should call this,
// after draining work at shutdown. A failed session requires process restart.
func Purge() error { return protected(func() error { memguard.Purge(); return nil }) }
