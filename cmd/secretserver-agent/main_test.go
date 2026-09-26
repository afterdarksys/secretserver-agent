package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	account = "11111111-1111-4111-8111-111111111111"
	profile = "22222222-2222-4222-8222-222222222222"
	device  = "33333333-3333-4333-8333-333333333333"
)

// fakeServer implements the agent-facing endpoints needed by the CLI; it does
// not verify proofs (covered in internal/agent) but checks request shapes.
func fakeServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/api/v1/agents/devices":
			if r.Header.Get("Authorization") != "Bearer admin-api-key" {
				w.WriteHeader(401)
				return
			}
			var e map[string]string
			json.NewDecoder(r.Body).Decode(&e)
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(map[string]string{"device_id": device, "account_id": e["account_id"], "profile_id": e["profile_id"], "public_key": e["public_key"]})
		case r.Header.Get("X-SecretServer-Signature") == "" || r.Header.Get("Authorization") != "":
			w.WriteHeader(401)
		case r.URL.Path == "/api/v1/agent/identity":
			fmt.Fprintf(w, `{"device_id":%q,"account_id":%q,"profile_id":%q,"grants":[{"alias":"app","service":"secret.read","resource":%q}]}`, device, account, profile, device)
		case r.URL.Path == "/api/v1/agent/access/app":
			fmt.Fprint(w, `{"data":{"value":"cli-secret"}}`)
		case r.URL.Path == "/api/v1/agent/variables/resolve":
			var req map[string]json.RawMessage
			json.NewDecoder(r.Body).Decode(&req)
			if doc, ok := req["document"]; ok {
				fmt.Fprintf(w, `{"document":%s,"variables":[]}`, bytes.ReplaceAll(doc, []byte("%%A%%"), []byte("resolved")))
				return
			}
			var tmpl string
			json.Unmarshal(req["template"], &tmpl)
			json.NewEncoder(w).Encode(map[string]string{"rendered": strings.ReplaceAll(tmpl, "%%A%%", "resolved")})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func invoke(args ...string) (string, string, error) {
	return invokeInput("", args...)
}

func invokeInput(stdin string, args ...string) (string, string, error) {
	var out, errOut bytes.Buffer
	err := run(context.Background(), args, strings.NewReader(stdin), &out, &errOut)
	return out.String(), errOut.String(), err
}

func privateDir(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// enrolled performs an API-key login and returns the state directory.
func enrolled(t *testing.T, server string) string {
	t.Helper()
	state := privateDir(t, "state")
	key := filepath.Join(t.TempDir(), "key")
	os.WriteFile(key, []byte("admin-api-key\n"), 0600)
	out, _, err := invoke("login", "--server", server, "--allow-loopback-http", "--account", account, "--profile", profile, "--name", "web-01", "--api-key-file", key, "--state-dir", state)
	if err != nil || !strings.Contains(out, device) {
		t.Fatalf("login: %v %s", err, out)
	}
	return state
}

func TestExitCodes(t *testing.T) {
	var buf bytes.Buffer
	if exitCode(nil, &buf) != 0 || buf.Len() != 0 {
		t.Fatal("success must exit 0 silently")
	}
	if exitCode(fmt.Errorf("parse: %w", flag.ErrHelp), &buf) != 0 {
		t.Fatal("help must exit 0")
	}
	if exitCode(errors.New("boom"), &buf) != 1 || !strings.Contains(buf.String(), "secretserver-agent: boom") {
		t.Fatal("failure must exit 1 with message")
	}
	_, stderr, err := invoke("status", "-h")
	if !errors.Is(err, flag.ErrHelp) || !strings.Contains(stderr, "-state-dir") {
		t.Fatalf("help not handled: %v %q", err, stderr)
	}
}

func TestArgumentErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"none":             {},
		"unknown":          {"delete"},
		"positional":       {"status", "extra"},
		"login-positional": {"login", "extra"},
		"bad-flag":         {"run", "--bogus"},
		"bad-duration":     {"run", "--poll", "soon"},
	} {
		if _, _, err := invoke(args...); err == nil {
			t.Errorf("%s: accepted %v", name, args)
		}
	}
}

func TestLoginValidation(t *testing.T) {
	server := fakeServer(t)
	key := filepath.Join(t.TempDir(), "key")
	os.WriteFile(key, []byte("admin-api-key"), 0644)
	base := []string{"--account", account, "--profile", profile, "--name", "web-01"}
	cases := map[string][]string{
		"plain-http":      append([]string{"login", "--server", "http://example.com", "--allow-loopback-http", "--state-dir", privateDir(t, "a")}, base...),
		"implicit-http":   append([]string{"login", "--server", server.URL, "--state-dir", privateDir(t, "b")}, base...),
		"server-path":     append([]string{"login", "--server", "https://example.com/api", "--state-dir", privateDir(t, "c")}, base...),
		"missing-account": {"login", "--server", "https://example.com", "--profile", profile, "--name", "x", "--state-dir", privateDir(t, "d")},
		"uppercase-uuid":  {"login", "--server", "https://example.com", "--account", strings.ToUpper(account), "--profile", profile, "--name", "x", "--state-dir", privateDir(t, "e")},
		"bad-name":        {"login", "--server", "https://example.com", "--account", account, "--profile", profile, "--name", "-x", "--state-dir", privateDir(t, "f")},
		"public-key-file": append([]string{"login", "--server", server.URL, "--allow-loopback-http", "--api-key-file", key, "--state-dir", privateDir(t, "g")}, base...),
		"relative-state":  append([]string{"login", "--server", server.URL, "--allow-loopback-http", "--state-dir", "state"}, base...),
	}
	for name, args := range cases {
		if _, _, err := invoke(args...); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestLoginStatusAccessRender(t *testing.T) {
	server := fakeServer(t)
	state := enrolled(t, server.URL)
	raw, _ := os.ReadFile(filepath.Join(state, "identity.json"))
	if bytes.Contains(raw, []byte("admin-api-key")) || !bytes.Contains(raw, []byte(device)) {
		t.Fatal("identity must record the device and never the bootstrap key")
	}
	if st, _ := os.Stat(filepath.Join(state, "identity.json")); st.Mode().Perm() != 0600 {
		t.Fatalf("identity mode %v", st.Mode())
	}
	if _, err := os.Stat(filepath.Join(state, ".lock")); !os.IsNotExist(err) {
		t.Fatal("login left its lock")
	}
	key := filepath.Join(t.TempDir(), "key")
	os.WriteFile(key, []byte("admin-api-key"), 0600)
	if _, _, err := invoke("login", "--server", server.URL, "--allow-loopback-http", "--account", account, "--profile", profile, "--name", "web-01", "--api-key-file", key, "--state-dir", state); err == nil || !strings.Contains(err.Error(), "already enrolled") {
		t.Fatalf("enrolled identity replaced: %v", err)
	}
	out, _, err := invoke("status", "--state-dir", state)
	if err != nil || !strings.Contains(out, `"alias":"app"`) {
		t.Fatalf("status: %v %s", err, out)
	}
	out, _, err = invoke("access", "--alias", "app", "--state-dir", state)
	if err != nil || !strings.Contains(out, "cli-secret") {
		t.Fatalf("access: %v %s", err, out)
	}
	if _, _, err = invokeInput("not json", "access", "--alias", "app", "--input", "-", "--state-dir", state); err == nil {
		t.Fatal("invalid access JSON accepted")
	}
	if _, _, err = invokeInput(`{"a":"`+strings.Repeat("x", 2<<20)+`"}`, "access", "--alias", "app", "--input", "-", "--state-dir", state); err == nil {
		t.Fatal("oversized access input accepted")
	}
	out, _, err = invokeInput("pw=%%A%%\n", "render", "--state-dir", state)
	if err != nil || out != "pw=resolved\n" {
		t.Fatalf("render: %v %q", err, out)
	}
	out, _, err = invokeInput(`{"pw":"%%A%%"}`, "render", "--json", "--state-dir", state)
	if err != nil || out != `{"pw":"resolved"}` {
		t.Fatalf("render --json: %v %q", err, out)
	}
	if out, _, err = invokeInput(`{"pw":`, "render", "--json", "--state-dir", state); err == nil || out != "" {
		t.Fatal("invalid JSON template accepted")
	}
	if out, _, err = invokeInput(strings.Repeat("x", (1<<20)+1), "render", "--state-dir", state); err == nil || out != "" {
		t.Fatal("oversized template accepted")
	}
}

func TestStateDirWithoutHome(t *testing.T) {
	server := fakeServer(t)
	state := enrolled(t, server.URL)
	t.Setenv("HOME", "")
	if _, _, err := invoke("status", "--state-dir", state); err != nil {
		t.Fatalf("explicit state-dir must work without HOME: %v", err)
	}
	if _, _, err := invoke("status"); err == nil {
		t.Fatal("missing state-dir accepted without HOME")
	}
}

func TestRunOutputMustBeSeparateFromState(t *testing.T) {
	server := fakeServer(t)
	state := enrolled(t, server.URL)
	link := filepath.Join(t.TempDir(), "link")
	os.Symlink(state, link)
	linkParent := filepath.Join(t.TempDir(), "parent")
	os.Symlink(filepath.Dir(state), linkParent)
	for name, out := range map[string]string{
		"same":           state,
		"parent":         filepath.Dir(state),
		"grandparent":    filepath.Dir(filepath.Dir(state)),
		"inside":         filepath.Join(state, "secrets"),
		"symlink":        link,
		"symlink-parent": filepath.Join(linkParent, "state"),
	} {
		if _, _, err := invoke("run", "--state-dir", state, "--output-dir", out); err == nil || !strings.Contains(err.Error(), "separate") {
			t.Errorf("%s: output-dir %s accepted: %v", name, out, err)
		}
	}
	if _, _, err := invoke("run", "--state-dir", state); err == nil || !strings.Contains(err.Error(), "output-dir is required") {
		t.Fatalf("missing output-dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(state, "identity.json")); err != nil {
		t.Fatal("identity removed by rejected run")
	}
}
