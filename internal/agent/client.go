package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	state State
	key   ed25519.PrivateKey
	http  *http.Client
}
type Grant struct {
	Alias    string `json:"alias"`
	Service  string `json:"service"`
	Resource string `json:"resource"`
	Backend  string `json:"backend,omitempty"`
}
type Identity struct {
	DeviceID  string  `json:"device_id"`
	AccountID string  `json:"account_id"`
	ProfileID string  `json:"profile_id"`
	Grants    []Grant `json:"grants"`
}
type HTTPError struct {
	Status int
	Code   string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("server request failed (HTTP %d, %s)", e.Status, e.Code)
}
func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("random source unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func NewClient(s State) (*Client, error) {
	server, err := ValidateURL(s.Server, s.AllowHTTP)
	if err != nil {
		return nil, err
	}
	s.Server = server
	key, err := base64.RawURLEncoding.DecodeString(s.PrivateKey)
	if err != nil || len(key) != 64 || !bytes.Equal(ed25519.NewKeyFromSeed(key[:32]), key) {
		return nil, errors.New("invalid device private key")
	}
	if !uuidPattern.MatchString(s.AccountID) || !uuidPattern.MatchString(s.ProfileID) || !namePattern.MatchString(s.Name) || (s.DeviceID != "" && !uuidPattern.MatchString(s.DeviceID)) {
		return nil, errors.New("invalid identity fields")
	}
	// Certificate-verified TLS 1.3 authenticates the server; redirects are never followed.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	return &Client{state: s, key: key, http: &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}}, nil
}
func NewState(server, account, profile, name string, allowHTTP bool) (State, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return State{}, err
	}
	s := State{Server: server, AccountID: account, ProfileID: profile, Name: name, AllowHTTP: allowHTTP, PrivateKey: base64.RawURLEncoding.EncodeToString(key)}
	_, err = NewClient(s)
	return s, err
}
func (c *Client) Enrollment() map[string]string {
	pub := base64.RawURLEncoding.EncodeToString(c.key.Public().(ed25519.PublicKey))
	msg := []byte("secretserver-enroll-v1\n" + c.state.AccountID + "\n" + c.state.ProfileID + "\n" + c.state.Name + "\n" + pub)
	return map[string]string{"account_id": c.state.AccountID, "profile_id": c.state.ProfileID, "name": c.state.Name, "public_key": pub, "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.key, msg))}
}
func (c *Client) Fingerprint() string {
	pub := c.Enrollment()["public_key"]
	sum := sha256.Sum256([]byte(pub))
	return hex.EncodeToString(sum[:])
}
func (c *Client) do(ctx context.Context, method, path, token, contentType string, body []byte, proof bool) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.state.Server+path, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("cannot create request")
	}
	req.Header.Set("Content-Type", contentType)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if proof {
		if c.state.DeviceID == "" {
			return nil, errors.New("device is not enrolled")
		}
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		nonce := randomToken(32)
		sum := sha256.Sum256(body)
		msg := []byte("secretserver-request-v1\n" + c.state.AccountID + "\n" + c.state.DeviceID + "\n" + method + "\n" + req.URL.RequestURI() + "\n" + ts + "\n" + nonce + "\n" + hex.EncodeToString(sum[:]))
		req.Header.Set("X-SecretServer-Account", c.state.AccountID)
		req.Header.Set("X-SecretServer-Device", c.state.DeviceID)
		req.Header.Set("X-SecretServer-Time", ts)
		req.Header.Set("X-SecretServer-Nonce", nonce)
		req.Header.Set("X-SecretServer-Signature", base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.key, msg)))
	}
	res, err := c.http.Do(req)
	if err != nil {
		// The URL error's cause (TLS, DNS, dial, redirect) carries no credentials.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return nil, fmt.Errorf("server connection failed: %v", err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, (4<<20)+1))
	if err != nil || len(raw) > 4<<20 {
		return nil, errors.New("invalid server response")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		// Do not reflect server bodies, which may include credentials, into logs.
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		code := "request_failed"
		switch e.Error {
		case "authorization_pending", "slow_down", "access_denied", "expired_token", "invalid_grant":
			code = e.Error
		}
		return nil, &HTTPError{Status: res.StatusCode, Code: code}
	}
	return raw, nil
}
func (c *Client) Enroll(ctx context.Context, token string, oauth bool) (State, error) {
	path := "/api/v1/agents/devices"
	if oauth {
		path = "/api/v1/agent/oauth/enroll"
	}
	data, _ := json.Marshal(c.Enrollment())
	raw, err := c.do(ctx, "POST", path, token, "application/json", data, false)
	if err != nil {
		return c.state, err
	}
	var got struct {
		DeviceID  string `json:"device_id"`
		AccountID string `json:"account_id"`
		ProfileID string `json:"profile_id"`
		PublicKey string `json:"public_key"`
	}
	if json.Unmarshal(raw, &got) != nil || got.AccountID != c.state.AccountID || got.ProfileID != c.state.ProfileID || got.PublicKey != c.Enrollment()["public_key"] || !uuidPattern.MatchString(got.DeviceID) {
		return c.state, errors.New("server enrollment binding mismatch")
	}
	c.state.DeviceID = got.DeviceID
	return c.state, nil
}

type DeviceAuthorization struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

var userCodePattern = regexp.MustCompile(`^[A-Za-z0-9-]{4,64}$`)

func (c *Client) StartOAuth(ctx context.Context) (DeviceAuthorization, error) {
	values := url.Values{"client_id": {"secretserver-agent"}}
	for k, v := range c.Enrollment() {
		values.Set(k, v)
	}
	raw, err := c.do(ctx, "POST", "/api/v1/agent/oauth/device", "", "application/x-www-form-urlencoded", []byte(values.Encode()), false)
	var d DeviceAuthorization
	if err != nil {
		return d, err
	}
	if json.Unmarshal(raw, &d) != nil || d.DeviceCode == "" || d.UserCode == "" || d.ExpiresIn < 1 || d.ExpiresIn > 600 || d.Interval < 5 || d.Interval > 60 {
		return d, errors.New("invalid device authorization response")
	}
	// Both values are printed to the operator's terminal; allow no control or escape sequences.
	if !userCodePattern.MatchString(d.UserCode) {
		return d, errors.New("invalid device authorization response")
	}
	u, err := url.Parse(d.VerificationURI)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || strings.IndexFunc(d.VerificationURI, func(r rune) bool { return r < 0x21 || r > 0x7e }) >= 0 {
		return d, errors.New("invalid authorization URL")
	}
	return d, nil
}
func (c *Client) WaitOAuth(ctx context.Context, d DeviceAuthorization) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(d.ExpiresIn)*time.Second)
	defer cancel()
	interval := time.Duration(d.Interval) * time.Second
	for {
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", ctx.Err()
		case <-timer.C:
		}
		form := url.Values{"client_id": {"secretserver-agent"}, "device_code": {d.DeviceCode}, "grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}}
		raw, err := c.do(ctx, "POST", "/api/v1/agent/oauth/token", "", "application/x-www-form-urlencoded", []byte(form.Encode()), false)
		if err != nil {
			var e *HTTPError
			if errors.As(err, &e) {
				if e.Code == "authorization_pending" {
					continue
				}
				if e.Code == "slow_down" {
					interval += 5 * time.Second
					continue
				}
			}
			return "", err
		}
		var token struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			Scope       string `json:"scope"`
		}
		if json.Unmarshal(raw, &token) != nil || token.AccessToken == "" || token.TokenType != "Bearer" || token.Scope != "agent:enroll" {
			return "", errors.New("invalid enrollment token response")
		}
		return token.AccessToken, nil
	}
}
func (c *Client) Identity(ctx context.Context) (Identity, error) {
	var id Identity
	raw, err := c.do(ctx, "GET", "/api/v1/agent/identity", "", "application/json", nil, true)
	if err != nil {
		return id, err
	}
	if json.Unmarshal(raw, &id) != nil || id.AccountID != c.state.AccountID || id.DeviceID != c.state.DeviceID || id.ProfileID != c.state.ProfileID || len(id.Grants) > 256 {
		return id, errors.New("server identity binding mismatch")
	}
	seen := map[string]bool{}
	for _, g := range id.Grants {
		if !namePattern.MatchString(g.Alias) || seen[g.Alias] || !strings.Contains("|secret.read|key.sign|database.issue|variable.resolve|", "|"+g.Service+"|") {
			return id, errors.New("invalid grant response")
		}
		seen[g.Alias] = true
	}
	return id, nil
}
func (c *Client) Access(ctx context.Context, alias string, payload []byte) ([]byte, error) {
	if !namePattern.MatchString(alias) {
		return nil, errors.New("invalid grant alias")
	}
	return c.do(ctx, "POST", "/api/v1/agent/access/"+alias, "", "application/json", payload, true)
}

// Render substitutes assigned variables without interpreting inserted values.
func (c *Client) Render(ctx context.Context, template string) (string, error) {
	body, err := json.Marshal(map[string]string{"template": template})
	if err != nil {
		return "", err
	}
	raw, err := c.do(ctx, "POST", "/api/v1/agent/variables/resolve", "", "application/json", body, true)
	if err != nil {
		return "", err
	}
	var result struct {
		Rendered *string `json:"rendered"`
	}
	if json.Unmarshal(raw, &result) != nil || result.Rendered == nil {
		return "", errors.New("invalid rendered response")
	}
	return *result.Rendered, nil
}
func (c *Client) ResolveDocument(ctx context.Context, document json.RawMessage) (json.RawMessage, error) {
	body, err := json.Marshal(map[string]json.RawMessage{"document": document})
	if err != nil {
		return nil, errors.New("invalid JSON document")
	}
	raw, err := c.do(ctx, "POST", "/api/v1/agent/variables/resolve", "", "application/json", body, true)
	if err != nil {
		return nil, err
	}
	var result struct {
		Document json.RawMessage `json:"document"`
	}
	if json.Unmarshal(raw, &result) != nil || len(result.Document) == 0 {
		return nil, errors.New("invalid resolved document")
	}
	return result.Document, nil
}
