//go:build !linux

package securemem

import "github.com/awnumar/memguard"

// MemGuard locks/protects allocations on supported platforms. Core-dump and
// hibernation policy outside Linux must also be enforced by the operator.
func harden(_ *memguard.LockedBuffer) error { return nil }
