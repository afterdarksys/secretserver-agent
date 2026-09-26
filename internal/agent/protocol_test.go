package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// serverMessage and serverVerify mirror secretserver.io internal/deviceauth so
// the agent's canonical form is checked against the server contract.
func serverMessage(account, device, method, uri, ts, nonce string, body []byte) []byte {
	sum := sha256.Sum256(body)
	return []byte("secretserver-request-v1\n" + account + "\n" + device + "\n" + method + "\n" + uri + "\n" + ts + "\n" + nonce + "\n" + hex.EncodeToString(sum[:]))
}

func serverVerify(pub ed25519.PublicKey, account, device, method, uri, ts, nonce, sig string, body []byte, now time.Time) error {
	n, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || ts != strconv.FormatInt(n, 10) || n < now.Unix()-60 || n > now.Unix()+5 {
		return fmt.Errorf("expired proof")
	}
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("invalid nonce")
	}
	s, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !ed25519.Verify(pub, serverMessage(account, device, method, uri, ts, nonce, body), s) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

type capturedRequest struct {
	method, uri string
	header      http.Header
	body        []byte
}

func enrolledClient(t *testing.T, handler http.HandlerFunc) (*Client, ed25519.PublicKey) {
	t.Helper()
	state, err := NewState("https://example.com", testAccount, testProfile, "test", false)
	if err != nil {
		t.Fatal(err)
	}
	state.DeviceID = testDevice
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	state.Server = server.URL
	state.AllowHTTP = true
	c, err := NewClient(state)
	if err != nil {
		t.Fatal(err)
	}
	return c, c.key.Public().(ed25519.PublicKey)
}

func TestRequestProofMatchesServerContract(t *testing.T) {
	var mu sync.Mutex
	var got []capturedRequest
	c, pub := enrolledClient(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, capturedRequest{r.Method, r.URL.RequestURI(), r.Header.Clone(), body})
		mu.Unlock()
		fmt.Fprint(w, `{"data":{"value":"v"}}`)
	})
	payload := []byte(`{"message":"aGVsbG8","purpose":"release"}`)
	if _, err := c.Access(context.Background(), "release-signing", payload); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Access(context.Background(), "release-signing", payload); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 requests, got %d", len(got))
	}
	r := got[0]
	h := r.header
	now := time.Now()
	verify := func(account, device, method, uri, ts, nonce string, body []byte) error {
		return serverVerify(pub, account, device, method, uri, ts, nonce, h.Get("X-SecretServer-Signature"), body, now)
	}
	acct, dev, ts, nonce := h.Get("X-SecretServer-Account"), h.Get("X-SecretServer-Device"), h.Get("X-SecretServer-Time"), h.Get("X-SecretServer-Nonce")
	if acct != testAccount || dev != testDevice || r.uri != "/api/v1/agent/access/release-signing" || !bytes.Equal(r.body, payload) {
		t.Fatalf("unexpected request binding: %s %s %s %q", acct, dev, r.uri, r.body)
	}
	if err := verify(acct, dev, r.method, r.uri, ts, nonce, r.body); err != nil {
		t.Fatalf("server contract rejected genuine proof: %v", err)
	}
	// Every signed field must be bound: any modification fails verification.
	tampered := map[string]func() error{
		"account": func() error {
			return verify("44444444-4444-4444-8444-444444444444", dev, r.method, r.uri, ts, nonce, r.body)
		},
		"device": func() error {
			return verify(acct, "44444444-4444-4444-8444-444444444444", r.method, r.uri, ts, nonce, r.body)
		},
		"method": func() error { return verify(acct, dev, "GET", r.uri, ts, nonce, r.body) },
		"uri":    func() error { return verify(acct, dev, r.method, "/api/v1/agent/access/other", ts, nonce, r.body) },
		"query":  func() error { return verify(acct, dev, r.method, r.uri+"?x=1", ts, nonce, r.body) },
		"time": func() error {
			n, _ := strconv.ParseInt(ts, 10, 64)
			return verify(acct, dev, r.method, r.uri, strconv.FormatInt(n-1, 10), nonce, r.body)
		},
		"nonce": func() error {
			return verify(acct, dev, r.method, r.uri, ts, got[1].header.Get("X-SecretServer-Nonce"), r.body)
		},
		"body": func() error {
			return verify(acct, dev, r.method, r.uri, ts, nonce, []byte(`{"message":"aGVsbG9=","purpose":"release"}`))
		},
	}
	for name, check := range tampered {
		if check() == nil {
			t.Errorf("modified %s accepted", name)
		}
	}
	// Expired proofs fail under the server's 60s/5s window.
	if serverVerify(pub, acct, dev, r.method, r.uri, ts, nonce, h.Get("X-SecretServer-Signature"), r.body, now.Add(61*time.Second)) == nil {
		t.Error("expired proof accepted")
	}
	// Wrong key fails.
	other, _, _ := ed25519.GenerateKey(nil)
	if serverVerify(other, acct, dev, r.method, r.uri, ts, nonce, h.Get("X-SecretServer-Signature"), r.body, now) == nil {
		t.Error("wrong key accepted")
	}
	// Nonces are 32 random bytes and never reused across requests.
	if raw, err := base64.RawURLEncoding.DecodeString(nonce); err != nil || len(raw) != 32 {
		t.Fatalf("nonce is not 32 base64url bytes: %q", nonce)
	}
	if nonce == got[1].header.Get("X-SecretServer-Nonce") {
		t.Fatal("nonce reused")
	}
	if n, _ := strconv.ParseInt(ts, 10, 64); n < now.Unix()-5 || n > now.Unix()+1 {
		t.Fatalf("timestamp not current Unix seconds: %s", ts)
	}
	if h.Get("Authorization") != "" {
		t.Fatal("bearer credential sent on device request")
	}
}

func TestEnrollmentSignatureMatchesServerContract(t *testing.T) {
	state, _ := NewState("https://example.com", testAccount, testProfile, "web-01", false)
	c, err := NewClient(state)
	if err != nil {
		t.Fatal(err)
	}
	e := c.Enrollment()
	pub, _ := base64.RawURLEncoding.DecodeString(e["public_key"])
	sig, _ := base64.RawURLEncoding.DecodeString(e["signature"])
	msg := "secretserver-enroll-v1\n" + testAccount + "\n" + testProfile + "\nweb-01\n" + e["public_key"]
	if len(pub) != 32 || !ed25519.Verify(pub, []byte(msg), sig) {
		t.Fatal("enrollment proof does not verify under server format")
	}
	for _, bad := range []string{
		"secretserver-enroll-v1\n" + testDevice + "\n" + testProfile + "\nweb-01\n" + e["public_key"],
		"secretserver-enroll-v1\n" + testAccount + "\n" + testDevice + "\nweb-01\n" + e["public_key"],
		"secretserver-enroll-v1\n" + testAccount + "\n" + testProfile + "\nweb-02\n" + e["public_key"],
	} {
		if ed25519.Verify(pub, []byte(bad), sig) {
			t.Fatal("enrollment proof not bound to its fields")
		}
	}
}

func TestEnrollRejectsServerBindingMismatch(t *testing.T) {
	good := func(c *Client) map[string]string {
		return map[string]string{"device_id": testDevice, "account_id": testAccount, "profile_id": testProfile, "public_key": c.Enrollment()["public_key"]}
	}
	cases := map[string]func(map[string]string){
		"account":   func(m map[string]string) { m["account_id"] = "44444444-4444-4444-8444-444444444444" },
		"profile":   func(m map[string]string) { m["profile_id"] = "44444444-4444-4444-8444-444444444444" },
		"key":       func(m map[string]string) { m["public_key"] = strings.Repeat("A", 43) },
		"device":    func(m map[string]string) { m["device_id"] = "../../etc" },
		"no-device": func(m map[string]string) { delete(m, "device_id") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			var c *Client
			c, _ = enrolledClient(t, func(w http.ResponseWriter, r *http.Request) {
				m := good(c)
				mutate(m)
				w.WriteHeader(201)
				json.NewEncoder(w).Encode(m)
			})
			c.state.DeviceID = ""
			if _, err := c.Enroll(context.Background(), "bootstrap-token", false); err == nil {
				t.Fatal("mismatched enrollment accepted")
			}
		})
	}
	t.Run("genuine", func(t *testing.T) {
		var c *Client
		var auth string
		c, _ = enrolledClient(t, func(w http.ResponseWriter, r *http.Request) {
			auth = r.Header.Get("Authorization")
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(good(c))
		})
		c.state.DeviceID = ""
		state, err := c.Enroll(context.Background(), "bootstrap-token", false)
		if err != nil || state.DeviceID != testDevice || auth != "Bearer bootstrap-token" {
			t.Fatalf("genuine enrollment failed: %v %q", err, auth)
		}
		dir := filepath.Join(t.TempDir(), "state")
		if err = SaveState(dir, state); err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(filepath.Join(dir, "identity.json"))
		if bytes.Contains(raw, []byte("bootstrap-token")) {
			t.Fatal("bootstrap credential persisted")
		}
	})
}

func TestIdentityRejectsUntrustedResponses(t *testing.T) {
	grants := func(g ...Grant) Identity {
		return Identity{DeviceID: testDevice, AccountID: testAccount, ProfileID: testProfile, Grants: g}
	}
	many := make([]Grant, 257)
	for i := range many {
		many[i] = Grant{Alias: fmt.Sprintf("a%d", i), Service: "secret.read"}
	}
	cases := map[string]Identity{
		"foreign-account": {DeviceID: testDevice, AccountID: testProfile, ProfileID: testProfile},
		"foreign-device":  {DeviceID: testProfile, AccountID: testAccount, ProfileID: testProfile},
		"foreign-profile": {DeviceID: testDevice, AccountID: testAccount, ProfileID: testDevice},
		"traversal-alias": grants(Grant{Alias: "../identity", Service: "secret.read"}),
		"dot-alias":       grants(Grant{Alias: ".secretserver-agent", Service: "secret.read"}),
		"slash-alias":     grants(Grant{Alias: "a/b", Service: "secret.read"}),
		"duplicate-alias": grants(Grant{Alias: "a", Service: "secret.read"}, Grant{Alias: "a", Service: "key.sign"}),
		"unknown-service": grants(Grant{Alias: "a", Service: "secret.write"}),
		"partial-service": grants(Grant{Alias: "a", Service: "secret"}),
		"too-many-grants": grants(many...),
	}
	for name, id := range cases {
		t.Run(name, func(t *testing.T) {
			c, _ := enrolledClient(t, func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(id) })
			if _, err := c.Identity(context.Background()); err == nil {
				t.Fatal("untrusted identity accepted")
			}
		})
	}
}

func TestServerErrorBodiesAreNotReflected(t *testing.T) {
	c, _ := enrolledClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		fmt.Fprint(w, `{"error":"leaked-secret-value"}`)
	})
	_, err := c.Access(context.Background(), "app", []byte("{}"))
	if err == nil || strings.Contains(err.Error(), "leaked-secret-value") {
		t.Fatalf("server body reflected into error: %v", err)
	}
	c, _ = enrolledClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write(bytes.Repeat([]byte("x"), (4<<20)+2))
	})
	if _, err = c.Access(context.Background(), "app", []byte("{}")); err == nil {
		t.Fatal("oversized response accepted")
	}
	if _, err = c.Access(context.Background(), "../identity", []byte("{}")); err == nil {
		t.Fatal("traversal alias accepted")
	}
}

func TestOAuthDeviceFlow(t *testing.T) {
	var polls int
	var c *Client
	c, _ = enrolledClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.ParseForm() != nil || r.PostForm.Get("client_id") != "secretserver-agent" {
			w.WriteHeader(400)
			return
		}
		switch r.URL.Path {
		case "/api/v1/agent/oauth/device":
			if r.PostForm.Get("public_key") != c.Enrollment()["public_key"] || r.PostForm.Get("signature") == "" {
				w.WriteHeader(400)
				return
			}
			fmt.Fprint(w, `{"device_code":"dc","user_code":"ABCDEF012345","verification_uri":"https://secretserver.example/agent/authorize","expires_in":600,"interval":5}`)
		case "/api/v1/agent/oauth/token":
			polls++
			if r.PostForm.Get("device_code") != "dc" || r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
				w.WriteHeader(400)
				return
			}
			if polls == 1 {
				w.WriteHeader(400)
				fmt.Fprint(w, `{"error":"authorization_pending"}`)
				return
			}
			fmt.Fprint(w, `{"access_token":"enroll-token","token_type":"Bearer","scope":"agent:enroll","expires_in":500}`)
		default:
			w.WriteHeader(404)
		}
	})
	auth, err := c.StartOAuth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	auth.Interval = 1 // speed up the test; StartOAuth enforces >= 5 from the server.
	token, err := c.WaitOAuth(context.Background(), auth)
	if err != nil || token != "enroll-token" || polls != 2 {
		t.Fatalf("device flow failed: %v %q polls=%d", err, token, polls)
	}
}

func TestOAuthRejectsUnsafeResponses(t *testing.T) {
	start := map[string]string{
		"http-uri":      `{"device_code":"dc","user_code":"ABCD1234","verification_uri":"http://evil.example/","expires_in":600,"interval":5}`,
		"userinfo-uri":  `{"device_code":"dc","user_code":"ABCD1234","verification_uri":"https://a@evil.example/","expires_in":600,"interval":5}`,
		"fast-interval": `{"device_code":"dc","user_code":"ABCD1234","verification_uri":"https://ok.example/","expires_in":600,"interval":1}`,
		"long-expiry":   `{"device_code":"dc","user_code":"ABCD1234","verification_uri":"https://ok.example/","expires_in":86400,"interval":5}`,
		"escape-code":   `{"device_code":"dc","user_code":"\u001b]0;pwned\u0007","verification_uri":"https://ok.example/","expires_in":600,"interval":5}`,
		"newline-code":  `{"device_code":"dc","user_code":"AB\nCD","verification_uri":"https://ok.example/","expires_in":600,"interval":5}`,
		"unicode-uri":   `{"device_code":"dc","user_code":"ABCD1234","verification_uri":"https://ok.example/\u202eevil","expires_in":600,"interval":5}`,
		"empty-code":    `{"device_code":"","user_code":"ABCD1234","verification_uri":"https://ok.example/","expires_in":600,"interval":5}`,
	}
	for name, body := range start {
		t.Run(name, func(t *testing.T) {
			c, _ := enrolledClient(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
			if _, err := c.StartOAuth(context.Background()); err == nil {
				t.Fatal("unsafe device authorization accepted")
			}
		})
	}
	tokens := map[string]string{
		"denied":      `{"error":"access_denied"}`,
		"expired":     `{"error":"expired_token"}`,
		"wrong-scope": `{"access_token":"t","token_type":"Bearer","scope":"admin"}`,
		"wrong-type":  `{"access_token":"t","token_type":"mac","scope":"agent:enroll"}`,
		"no-token":    `{"token_type":"Bearer","scope":"agent:enroll"}`,
	}
	for name, body := range tokens {
		t.Run(name, func(t *testing.T) {
			c, _ := enrolledClient(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(body, `"error"`) {
					w.WriteHeader(400)
				}
				fmt.Fprint(w, body)
			})
			if _, err := c.WaitOAuth(context.Background(), DeviceAuthorization{DeviceCode: "dc", ExpiresIn: 5, Interval: 1}); err == nil {
				t.Fatal("invalid token response accepted")
			}
		})
	}
}

func TestRenderAndResolveDocumentFailClosed(t *testing.T) {
	var sent map[string]json.RawMessage
	c, _ := enrolledClient(t, func(w http.ResponseWriter, r *http.Request) {
		sent = nil
		json.NewDecoder(r.Body).Decode(&sent)
		if _, ok := sent["template"]; ok {
			fmt.Fprint(w, `{"rendered":"pw=\"q\nx","variables":["A"]}`)
			return
		}
		fmt.Fprint(w, `{"document":{"password":"q\"\n"},"variables":["A"]}`)
	})
	out, err := c.Render(context.Background(), "pw=%%A%%")
	if err != nil || out != "pw=\"q\nx" {
		t.Fatalf("render: %v %q", err, out)
	}
	if string(sent["template"]) != `"pw=%%A%%"` {
		t.Fatalf("template not sent verbatim: %s", sent["template"])
	}
	doc, err := c.ResolveDocument(context.Background(), json.RawMessage(`{"password":"%%A%%"}`))
	if err != nil || !json.Valid(doc) {
		t.Fatalf("document: %v %s", err, doc)
	}
	if _, err = c.ResolveDocument(context.Background(), json.RawMessage(`{"password":`)); err == nil {
		t.Fatal("invalid JSON template accepted")
	}
	for name, body := range map[string]string{"no-rendered": `{"variables":[]}`, "error": ``} {
		t.Run(name, func(t *testing.T) {
			c, _ := enrolledClient(t, func(w http.ResponseWriter, r *http.Request) {
				if body == "" {
					w.WriteHeader(403)
					return
				}
				fmt.Fprint(w, body)
			})
			if out, err := c.Render(context.Background(), "%%A%%"); err == nil || out != "" {
				t.Fatal("partial render accepted")
			}
			if doc, err := c.ResolveDocument(context.Background(), json.RawMessage(`{}`)); err == nil || doc != nil {
				t.Fatal("partial document accepted")
			}
		})
	}
}
