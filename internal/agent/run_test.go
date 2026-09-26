package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func privateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func exists(path string) bool { _, err := os.Lstat(path); return err == nil }

// fixtureServer serves an identity with the given grants and per-alias data;
// fail makes every request return HTTP 500 while set.
func fixtureServer(t *testing.T, grants []Grant, data map[string]string, fail *atomic.Bool) *Client {
	c, _ := enrolledClient(t, func(w http.ResponseWriter, r *http.Request) {
		if fail != nil && fail.Load() {
			w.WriteHeader(500)
			return
		}
		if r.URL.Path == "/api/v1/agent/identity" {
			json.NewEncoder(w).Encode(Identity{DeviceID: testDevice, AccountID: testAccount, ProfileID: testProfile, Grants: grants})
			return
		}
		alias := strings.TrimPrefix(r.URL.Path, "/api/v1/agent/access/")
		body, ok := data[alias]
		if !ok {
			w.WriteHeader(403)
			return
		}
		fmt.Fprint(w, body)
	})
	return c
}

func TestRunDeliversPrivateFilesAndCleansOnShutdown(t *testing.T) {
	grants := []Grant{
		{Alias: "app-config", Service: "secret.read", Resource: testDevice},
		{Alias: "sudo-password", Service: "variable.resolve", Resource: testDevice},
		{Alias: "release-signing", Service: "key.sign", Resource: "k"},
		{Alias: "database", Service: "database.issue", Resource: testDevice},
	}
	data := map[string]string{
		"app-config":    `{"id":"x","data":{"user":"u","pass":"p\"\n<&>"}}`,
		"sudo-password": `{"data":{"value":"v"}}`,
	}
	c := fixtureServer(t, grants, data, nil)
	dir := privateDir(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, dir, time.Second, func(err error) { t.Log("refresh:", err) }) }()
	app, sudo := filepath.Join(dir, "app-config.json"), filepath.Join(dir, "sudo-password.json")
	waitFor(t, func() bool { return exists(app) && exists(sudo) })
	for _, p := range []string{app, sudo, filepath.Join(dir, ".secretserver-agent"), filepath.Join(dir, ".lock")} {
		st, err := os.Lstat(p)
		if err != nil || st.Mode().Perm() != 0600 || !st.Mode().IsRegular() {
			t.Fatalf("%s not a private regular file: %v %v", p, st.Mode(), err)
		}
	}
	var got map[string]string
	raw, _ := os.ReadFile(app)
	if json.Unmarshal(raw, &got) != nil || got["user"] != "u" || got["pass"] != "p\"\n<&>" || len(got) != 2 {
		t.Fatalf("delivered data wrong: %s", raw)
	}
	for _, name := range []string{"release-signing.json", "database.json"} {
		if exists(filepath.Join(dir, name)) {
			t.Fatalf("operation grant %s must never be delivered automatically", name)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("shutdown returned error: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != ".secretserver-agent" {
			t.Fatalf("shutdown left %s", e.Name())
		}
	}
}

func TestRunRemovesStaleFilesBeforeNetworkAndOnFailure(t *testing.T) {
	grants := []Grant{{Alias: "app", Service: "secret.read", Resource: testDevice}}
	var fail atomic.Bool
	c := fixtureServer(t, grants, map[string]string{"app": `{"data":{"k":"v"}}`}, &fail)
	dir := privateDir(t)
	// First run establishes ownership of the directory.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, dir, time.Second, nil) }()
	waitFor(t, func() bool { return exists(filepath.Join(dir, "app.json")) })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// Simulate a crash leaving material behind, then restart with the server down.
	for _, name := range []string{"app.json", "old.json", ".tmp-partial"} {
		os.WriteFile(filepath.Join(dir, name), []byte("stale"), 0600)
	}
	fail.Store(true)
	ctx, cancel = context.WithCancel(context.Background())
	var mu sync.Mutex
	var reports []error
	go func() {
		done <- c.Run(ctx, dir, time.Second, func(err error) { mu.Lock(); reports = append(reports, err); mu.Unlock() })
	}()
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(reports) > 0 })
	for _, name := range []string{"app.json", "old.json", ".tmp-partial"} {
		if exists(filepath.Join(dir, name)) {
			t.Fatalf("stale %s survived restart while server unavailable", name)
		}
	}
	// A transient failure keeps the runner alive and recovers.
	fail.Store(false)
	waitFor(t, func() bool { return exists(filepath.Join(dir, "app.json")) })
	fail.Store(true)
	waitFor(t, func() bool { return !exists(filepath.Join(dir, "app.json")) })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRunFailsClosedOnInvalidDelivery(t *testing.T) {
	cases := map[string]struct {
		grants []Grant
		data   map[string]string
	}{
		"non-string-values": {[]Grant{{Alias: "app", Service: "secret.read"}}, map[string]string{"app": `{"data":{"k":1}}`}},
		"missing-data":      {[]Grant{{Alias: "app", Service: "secret.read"}}, map[string]string{"app": `{"value":"v"}`}},
		"not-json":          {[]Grant{{Alias: "app", Service: "secret.read"}}, map[string]string{"app": `v`}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := fixtureServer(t, tc.grants, tc.data, nil)
			dir := privateDir(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reported := make(chan error, 10)
			done := make(chan error, 1)
			go func() { done <- c.Run(ctx, dir, time.Second, func(err error) { reported <- err }) }()
			select {
			case <-reported:
			case <-time.After(10 * time.Second):
				t.Fatal("invalid delivery not reported")
			}
			entries, _ := os.ReadDir(dir)
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".json") || strings.HasPrefix(e.Name(), ".tmp-") {
					t.Fatalf("invalid delivery left %s", e.Name())
				}
			}
			cancel()
			<-done
		})
	}
}

func TestRunRejectsUnsafeDirectories(t *testing.T) {
	c := fixtureServer(t, nil, nil, nil)
	base := t.TempDir()
	public := filepath.Join(base, "public")
	os.Mkdir(public, 0755)
	target := privateDir(t)
	link := filepath.Join(base, "link")
	os.Symlink(target, link)
	foreign := privateDir(t)
	os.WriteFile(filepath.Join(foreign, ".secretserver-agent"), []byte("https://other\n"+testAccount+"\n"+testDevice+"\n"), 0600)
	os.WriteFile(filepath.Join(foreign, "keep.json"), []byte("keep"), 0600)
	for name, dir := range map[string]string{"relative": "out", "unclean": base + "/x/../public", "group-readable": public, "symlink": link, "other-agent": foreign} {
		if err := c.Run(context.Background(), dir, time.Second, nil); err == nil {
			t.Errorf("%s output directory accepted", name)
		}
	}
	if raw, _ := os.ReadFile(filepath.Join(foreign, "keep.json")); string(raw) != "keep" {
		t.Fatal("foreign agent directory modified")
	}
	for _, d := range []time.Duration{0, 999 * time.Millisecond, 2 * time.Hour} {
		if err := c.Run(context.Background(), privateDir(t), d, nil); err == nil {
			t.Errorf("poll interval %v accepted", d)
		}
	}
}
