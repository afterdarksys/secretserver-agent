package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testAccount = "11111111-1111-4111-8111-111111111111"
const testProfile = "22222222-2222-4222-8222-222222222222"
const testDevice = "33333333-3333-4333-8333-333333333333"

func TestURLPolicy(t *testing.T) {
	for _, u := range []string{"http://example.com", "http://localhost", "https://user:pass@example.com", "https://example.com/api/v1", "https://example.com?x=1", "file:///tmp/x"} {
		if _, err := ValidateURL(u, true); err == nil {
			t.Errorf("accepted %s", u)
		}
	}
	if _, err := ValidateURL("http://127.0.0.1:8080", false); err == nil {
		t.Fatal("implicit HTTP")
	}
	if _, err := ValidateURL("https://example.com", false); err != nil {
		t.Fatal(err)
	}
}
func TestStateAndCredentialPermissions(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	state, err := NewState("https://example.com", testAccount, testProfile, "test", false)
	if err != nil {
		t.Fatal(err)
	}
	if err = SaveState(dir, state); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadState(dir)
	if err != nil || loaded != state {
		t.Fatal("state roundtrip", err)
	}
	path := filepath.Join(dir, "identity.json")
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadState(dir); err == nil {
		t.Fatal("public keyfile accepted")
	}
	if _, err = ReadCredential(path); err == nil {
		t.Fatal("public credential accepted")
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadCredential(link); err == nil {
		t.Fatal("symlink accepted")
	}
	unlock, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err = Lock(dir); err == nil {
		t.Fatal("duplicate lock accepted")
	}
}
func TestSignedIdentityAndRedirectRefusal(t *testing.T) {
	state, _ := NewState("https://example.com", testAccount, testProfile, "test", false)
	state.DeviceID = testDevice
	key, _ := base64.RawURLEncoding.DecodeString(state.PrivateKey)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sum := sha256.Sum256(nil)
		msg := []byte("secretserver-request-v1\n" + testAccount + "\n" + testDevice + "\nGET\n/api/v1/agent/identity\n" + r.Header.Get("X-SecretServer-Time") + "\n" + r.Header.Get("X-SecretServer-Nonce") + "\n" + hex.EncodeToString(sum[:]))
		sig, _ := base64.RawURLEncoding.DecodeString(r.Header.Get("X-SecretServer-Signature"))
		if !ed25519.Verify(ed25519.PrivateKey(key).Public().(ed25519.PublicKey), msg, sig) {
			t.Error("bad signature")
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("account token leaked")
		}
		json.NewEncoder(w).Encode(Identity{DeviceID: testDevice, AccountID: testAccount, ProfileID: testProfile, Grants: []Grant{}})
	}))
	defer server.Close()
	state.Server = server.URL
	state.AllowHTTP = true
	c, _ := NewClient(state)
	if _, err := c.Identity(context.Background()); err != nil {
		t.Fatal(err)
	}
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, server.URL, 302) }))
	defer redirect.Close()
	c.state.Server = redirect.URL
	if _, err := c.Identity(context.Background()); err == nil || !strings.Contains(err.Error(), "redirect refused") {
		t.Fatal("followed redirect", err)
	}
}
func TestRunClearsRevokedFiles(t *testing.T) {
	state, _ := NewState("https://example.com", testAccount, testProfile, "test", false)
	state.DeviceID = testDevice
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "identity") {
			calls++
			if calls > 1 {
				w.WriteHeader(401)
				return
			}
			json.NewEncoder(w).Encode(Identity{DeviceID: testDevice, AccountID: testAccount, ProfileID: testProfile, Grants: []Grant{{Alias: "database-password", Service: "secret.read", Resource: testDevice}}})
			return
		}
		fmt.Fprint(w, `{"data":{"value":"fixture-secret"}}`)
	}))
	defer server.Close()
	state.Server = server.URL
	state.AllowHTTP = true
	c, _ := NewClient(state)
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	err := c.Run(context.Background(), dir, time.Second, nil)
	if err == nil {
		t.Fatal("revocation must stop runner")
	}
	if _, err = os.Stat(filepath.Join(dir, "database-password.json")); !os.IsNotExist(err) {
		t.Fatal("revoked secret remains")
	}
	if _, err = os.Stat(filepath.Join(dir, ".lock")); !os.IsNotExist(err) {
		t.Fatal("lock remains")
	}
}
func TestRunRejectsForeignDirectory(t *testing.T) {
	state, _ := NewState("https://example.com", testAccount, testProfile, "test", false)
	state.DeviceID = testDevice
	c, _ := NewClient(state)
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	os.WriteFile(filepath.Join(dir, "important.json"), []byte("keep"), 0600)
	if c.Run(context.Background(), dir, time.Second, nil) == nil {
		t.Fatal("foreign directory accepted")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "important.json"))
	if string(raw) != "keep" {
		t.Fatal("foreign file removed")
	}
}

func TestDocumentGrantRejectedByDeviceIdentity(t *testing.T) {
	for _, service := range []string{"document.read", "documents:manage", "document.preview", "document.download"} {
		t.Run(service, func(t *testing.T) {
			state, _ := NewState("https://example.com", testAccount, testProfile, "test", false)
			state.DeviceID = testDevice
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(Identity{DeviceID: testDevice, AccountID: testAccount, ProfileID: testProfile, Grants: []Grant{{Alias: "private-pdf", Service: service, Resource: testDevice}}})
			}))
			defer server.Close()
			state.Server = server.URL
			state.AllowHTTP = true
			c, _ := NewClient(state)
			if _, err := c.Identity(context.Background()); err == nil {
				t.Fatal("accepted unsupported document grant")
			}
		})
	}
}
