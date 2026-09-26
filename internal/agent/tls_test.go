package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func tlsClient(t *testing.T, maxVersion uint16, trust bool) (*Client, error) {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Identity{DeviceID: testDevice, AccountID: testAccount, ProfileID: testProfile, Grants: []Grant{}})
	}))
	server.TLS = &tls.Config{MaxVersion: maxVersion}
	server.StartTLS()
	t.Cleanup(server.Close)
	state, _ := NewState(server.URL, testAccount, testProfile, "test", false)
	state.DeviceID = testDevice
	c, err := NewClient(state)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := c.http.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatal("client transport must verify certificates and require TLS 1.3")
	}
	if trust {
		pool := x509.NewCertPool()
		pool.AddCert(server.Certificate())
		transport.TLSClientConfig.RootCAs = pool
	}
	_, err = c.Identity(context.Background())
	return c, err
}

func TestTLSPolicy(t *testing.T) {
	if _, err := tlsClient(t, tls.VersionTLS13, true); err != nil {
		t.Fatalf("trusted TLS 1.3 server rejected: %v", err)
	}
	if _, err := tlsClient(t, tls.VersionTLS13, false); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("untrusted certificate accepted or undiagnosed: %v", err)
	}
	if _, err := tlsClient(t, tls.VersionTLS12, true); err == nil {
		t.Fatal("TLS 1.2 server accepted")
	}
}
