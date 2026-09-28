package agent

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func ValidateURL(raw string, allowHTTP bool) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("server must be an HTTPS origin without a path")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && (u.Scheme != "http" || !allowHTTP || ip == nil || !ip.IsLoopback()) {
		return "", errors.New("HTTPS required; development HTTP requires an explicit loopback IP")
	}
	return strings.TrimRight(raw, "/"), nil
}

type State struct {
	Server     string `json:"server"`
	AllowHTTP  bool   `json:"allow_loopback_http,omitempty"`
	AccountID  string `json:"account_id"`
	ProfileID  string `json:"profile_id"`
	DeviceID   string `json:"device_id"`
	Name       string `json:"name"`
	PrivateKey string `json:"private_key"`
}

func privateRoot(dir string) (*os.Root, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, errors.New("state/output directory must be an absolute clean path")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, errors.New("cannot create private directory")
	}
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("directory must be private (0700) and not a symlink")
	}
	return os.OpenRoot(dir)
}
func ReadCredential(path string) (string, error) {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return "", errors.New("credential must be a regular private file (0600)")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("cannot open credential")
	}
	defer f.Close()
	got, err := f.Stat()
	if err != nil || !os.SameFile(st, got) {
		return "", errors.New("credential changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(raw) > 65536 {
		return "", errors.New("invalid credential")
	}
	token := strings.TrimSpace(string(raw))
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", errors.New("credential must contain one token")
	}
	return token, nil
}
func LoadState(dir string) (State, error) {
	var s State
	r, err := privateRoot(dir)
	if err != nil {
		return s, err
	}
	defer r.Close()
	st, err := r.Lstat("identity.json")
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return s, errors.New("identity.json missing or not private")
	}
	f, err := r.Open("identity.json")
	if err != nil {
		return s, errors.New("cannot read identity")
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 16384))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil || d.Decode(new(any)) != io.EOF {
		return s, errors.New("invalid identity")
	}
	return s, nil
}
func SaveState(dir string, s State) error {
	r, err := privateRoot(dir)
	if err != nil {
		return err
	}
	defer r.Close()
	raw, err := json.MarshalIndent(s, "", "  ")
	defer clear(raw)
	if err != nil {
		return err
	}
	return atomicWrite(r, "identity.json", raw)
}
func atomicWrite(r *os.Root, name string, data []byte) error {
	tmp := ".tmp-" + randomToken(16)
	f, err := r.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer r.Remove(tmp)
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = r.Rename(tmp, name); err != nil {
		return err
	}
	return nil
}
