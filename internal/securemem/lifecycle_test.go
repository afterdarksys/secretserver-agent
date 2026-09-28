package securemem

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
)

func TestProtectedLifecycle(t *testing.T) {
	src := []byte("secret-marker")
	b, err := Consume(src)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Destroy()
	if !bytes.Equal(src, make([]byte, len(src))) {
		t.Fatal("source not wiped")
	}
	if b.memory == nil || b.memory.IsMutable() {
		t.Fatal("missing read-only locked buffer")
	}
	if bytes.Contains([]byte(fmt.Sprintf("%v %#v", b, b)), []byte("secret-marker")) {
		t.Fatal("secret formatting leak")
	}
	if _, err = json.Marshal(b); err == nil {
		t.Fatal("secret serialization permitted")
	}
	if err = b.WithBytes(func(p []byte) error {
		if !bytes.Equal(p, []byte("secret-marker")) {
			t.Fatal("roundtrip")
		}
		return errors.New("callback error")
	}); err == nil {
		t.Fatal("callback error lost")
	}
	if err = b.WithBytes(func([]byte) error { panic("sensitive panic") }); !errors.Is(err, ErrUnavailable) {
		t.Fatal("panic not redacted", err)
	}
	if err = b.WithBytes(func(p []byte) error {
		if !bytes.Equal(p, []byte("secret-marker")) {
			t.Fatal("callback cleanup damaged key")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = b.Destroy(); err != nil {
		t.Fatal(err)
	}
	b.Destroy()
	if b.Len() != 0 {
		t.Fatal("destroy did not invalidate")
	}
	if err = b.WithBytes(func([]byte) error { t.Fatal("used destroyed key"); return nil }); !errors.Is(err, ErrDestroyed) {
		t.Fatal(err)
	}
}
func TestConcurrentCopyAndDestroy(t *testing.T) {
	a, err := Consume([]byte("abcd"))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Destroy()
	b, err := New(4)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Destroy()
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if n%2 == 0 {
					if e := a.CopyTo(b); e != nil {
						t.Error(e)
					}
				} else {
					if e := b.CopyTo(a); e != nil {
						t.Error(e)
					}
				}
			}
		}(n)
	}
	wg.Wait()
	if _, err = a.WriteAt([]byte("xy"), 3); err == nil {
		t.Fatal("out of bounds")
	}
	if _, err = a.WriteAt([]byte("z"), 0); err != nil {
		t.Fatal(err)
	}
	if err = a.WithBytes(func(p []byte) error {
		if p[0] != 'z' {
			t.Fatal("write not persisted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
func TestConsumeFailureStillWipes(t *testing.T) {
	src := bytes.Repeat([]byte{0x7f}, MaxSecretSize+1)
	if b, err := Consume(src); err == nil || b != nil {
		t.Fatal("accepted oversized secret")
	}
	if !bytes.Equal(src, make([]byte, len(src))) {
		t.Fatal("failure did not wipe source")
	}
}
