//go:build linux || darwin

package securemem

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Lower process limits only in a disposable subprocess, never the test runner.
func TestLockFailureIsClosed(t *testing.T) {
	if os.Getenv("SS_MEMORY_LOCK_FAILURE_CHILD") == "1" {
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
			t.Fatal(err)
		}
		src := []byte("disposable-test-secret")
		b, err := Consume(src)
		if b != nil || !errors.Is(err, ErrUnavailable) {
			t.Fatalf("protection unexpectedly succeeded: %v", err)
		}
		if !bytes.Equal(src, make([]byte, len(src))) {
			t.Fatal("source not wiped on lock failure")
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLockFailureIsClosed$", "-test.v")
	cmd.Env = append(os.Environ(), "SS_MEMORY_LOCK_FAILURE_CHILD=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("lock failure subprocess: %v\n%s", err, output)
	}
}

// One successful allocation followed by exhaustion exercises purge while other
// live handles exist, and ensures repeated retries neither allocate nor hang.
func TestPartialLockExhaustion(t *testing.T) {
	if os.Getenv("SS_MEMORY_PARTIAL_CHILD") == "1" {
		page := uint64(os.Getpagesize())
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: page, Max: page}); err != nil {
			t.Fatal(err)
		}
		first, err := Consume([]byte("first"))
		if err != nil {
			t.Fatal("first allocation", err)
		}
		defer first.Destroy()
		for i := 0; i < 100; i++ {
			src := []byte("second")
			b, err := Consume(src)
			if b != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("exhaustion not closed: %v", err)
			}
			if !bytes.Equal(src, make([]byte, len(src))) {
				t.Fatal("source not wiped")
			}
			if err := first.WithBytes(func([]byte) error { t.Fatal("stale view exposed"); return nil }); !errors.Is(err, ErrUnavailable) {
				t.Fatal("stale handle", err)
			}
		}
		if first.Len() != 0 {
			t.Fatal("purged handle length")
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPartialLockExhaustion$", "-test.v")
	cmd.Env = append(os.Environ(), "SS_MEMORY_PARTIAL_CHILD=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("partial exhaustion: %v\n%s", err, output)
	}
}
