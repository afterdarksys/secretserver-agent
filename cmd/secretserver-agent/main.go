package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/afterdarksys/secretserver-agent/internal/agent"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(exitCode(run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr), os.Stderr))
}

func exitCode(err error, stderr io.Writer) int {
	if err == nil || errors.Is(err, flag.ErrHelp) {
		return 0
	}
	fmt.Fprintln(stderr, "secretserver-agent:", err)
	return 1
}

// beneath reports whether the existing directory path is dir or lies beneath
// it. Symlinks are resolved and ancestors compared by file identity, so
// case-insensitive spellings and alternate links cannot evade the check.
func beneath(path, dir string) bool {
	path, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	target, err := os.Stat(dir)
	if err != nil {
		return false
	}
	for {
		if st, e := os.Stat(path); e == nil && os.SameFile(st, target) {
			return true
		}
		parent := filepath.Dir(path)
		if parent == path {
			return false
		}
		path = parent
	}
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: secretserver-agent login|status|access|render|run [options]")
	}
	// Without a home directory, --state-dir must be given explicitly.
	defaultState := ""
	if home, e := os.UserHomeDir(); e == nil {
		defaultState = filepath.Join(home, ".config", "secretserver-agent")
	}
	var err error
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(stderr)
	stateDir := f.String("state-dir", defaultState, "private device identity directory")
	switch args[0] {
	case "login":
		server := f.String("server", "https://api.secretserver.io", "Secret Server HTTPS origin")
		account := f.String("account", "", "expected account UUID (required)")
		profile := f.String("profile", "", "admin-assigned profile UUID (required)")
		name := f.String("name", "", "device name (letters, digits, dots, hyphens, underscores)")
		tokenFile := f.String("api-key-file", "", "0600 file with an account-admin API key; otherwise use OAuth2")
		allowHTTP := f.Bool("allow-loopback-http", false, "development only: allow HTTP to a loopback IP")
		if err = f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return errors.New("unexpected arguments")
		}
		unlock, err := agent.Lock(*stateDir)
		if err != nil {
			return err
		}
		defer unlock()
		state, err := agent.NewState(*server, *account, *profile, *name, *allowHTTP)
		if err != nil {
			return err
		}
		if _, e := os.Lstat(filepath.Join(*stateDir, "identity.json")); e == nil {
			prior, e := agent.LoadState(*stateDir)
			if e != nil {
				return e
			}
			if prior.DeviceID != "" {
				return errors.New("already enrolled; revoke the existing device before replacing its identity")
			}
			if prior.Server != state.Server || prior.AccountID != state.AccountID || prior.ProfileID != state.ProfileID || prior.Name != state.Name || prior.AllowHTTP != state.AllowHTTP {
				return errors.New("pending enrollment differs; retain or remove the pending identity deliberately")
			}
			state = prior
		} else if !os.IsNotExist(e) {
			return errors.New("cannot inspect identity")
		}
		if err = agent.SaveState(*stateDir, state); err != nil {
			return err
		}
		client, err := agent.NewClient(state)
		if err != nil {
			return err
		}
		var token string
		oauth := *tokenFile == ""
		if oauth {
			auth, err := client.StartOAuth(ctx)
			if err != nil {
				return err
			}
			fmt.Fprintf(stderr, "Open %s\nEnter code: %s\nConfirm device fingerprint: %s\n", auth.VerificationURI, auth.UserCode, client.Fingerprint())
			token, err = client.WaitOAuth(ctx, auth)
			if err != nil {
				return err
			}
		} else {
			token, err = agent.ReadCredential(*tokenFile)
			if err != nil {
				return err
			}
		}
		state, err = client.Enroll(ctx, token, oauth)
		if err != nil {
			return err
		}
		if err = agent.SaveState(*stateDir, state); err != nil {
			return err
		}
		identity, err := client.Identity(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(identity)
	case "status", "access", "render", "run":
		jsonDocument := f.Bool("json", false, "resolve JSON string values instead of raw text")
		alias := f.String("alias", "", "assigned resource alias for access")
		input := f.String("input", "", "JSON request file for access; '-' reads stdin")
		output := f.String("output-dir", "", "dedicated private secret output directory for run")
		poll := f.Duration("poll", 30*time.Second, "assignment refresh interval for run")
		if err = f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return errors.New("unexpected arguments")
		}
		state, err := agent.LoadState(*stateDir)
		if err != nil {
			return err
		}
		client, err := agent.NewClient(state)
		if err != nil {
			return err
		}
		if args[0] == "status" {
			identity, err := client.Identity(ctx)
			if err != nil {
				return err
			}
			return json.NewEncoder(stdout).Encode(identity)
		}
		if args[0] == "run" {
			// Never put delivered secrets in or above the directory holding the private key.
			out, err := filepath.Abs(*output)
			if err != nil || *output == "" {
				return errors.New("output-dir is required")
			}
			if _, err = os.Stat(*stateDir); err != nil {
				return errors.New("cannot inspect state-dir")
			}
			// The output directory may not exist yet: check its deepest existing ancestor.
			existing := out
			for {
				if _, e := os.Stat(existing); e == nil {
					break
				}
				parent := filepath.Dir(existing)
				if parent == existing {
					return errors.New("cannot resolve output-dir")
				}
				existing = parent
			}
			if beneath(existing, *stateDir) || (existing == out && beneath(*stateDir, out)) {
				return errors.New("output-dir must be separate from state-dir")
			}
			return client.Run(ctx, out, *poll, func(err error) { fmt.Fprintln(stderr, "refresh:", err) })
		}
		if args[0] == "render" {
			reader := stdin
			if *input != "" && *input != "-" {
				file, e := os.Open(*input)
				if e != nil {
					return errors.New("cannot open template")
				}
				defer file.Close()
				reader = file
			}
			raw, e := io.ReadAll(io.LimitReader(reader, (1<<20)+1))
			if e != nil || len(raw) > 1<<20 {
				return errors.New("template exceeds size limit")
			}
			if *jsonDocument {
				out, e := client.ResolveDocument(ctx, raw)
				if e != nil {
					return e
				}
				_, e = stdout.Write(out)
				return e
			}
			out, e := client.Render(ctx, string(raw))
			if e != nil {
				return e
			}
			_, e = io.WriteString(stdout, out)
			return e
		}
		body := []byte("{}")
		if *input != "" {
			reader := stdin
			var file *os.File
			if *input != "-" {
				file, err = os.Open(*input)
				if err != nil {
					return errors.New("cannot open request input")
				}
				defer file.Close()
				reader = file
			}
			body, err = io.ReadAll(io.LimitReader(reader, (2<<20)+1))
			if err != nil || len(body) > 2<<20 || !json.Valid(body) {
				return errors.New("invalid or oversized request JSON")
			}
		}
		raw, err := client.Access(ctx, *alias, body)
		if err != nil {
			return err
		}
		_, err = stdout.Write(append(raw, '\n'))
		return err
	default:
		return errors.New("unknown command; use login, status, access, render, or run")
	}
}
