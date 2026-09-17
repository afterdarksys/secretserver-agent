package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Lock serializes processes using a state directory. A crashed process leaves
// the lock for an operator to inspect; it is never silently stolen.
func Lock(dir string) (func(), error) {
	r, err := privateRoot(dir)
	if err != nil {
		return nil, err
	}
	f, err := r.OpenFile(".lock", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		r.Close()
		return nil, errors.New("directory is locked; inspect the running agent before removing .lock")
	}
	_, err = fmt.Fprintf(f, "%d\n", os.Getpid())
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		r.Remove(".lock")
		r.Close()
		return nil, errors.New("cannot write lock")
	}
	return func() { r.Remove(".lock"); r.Close() }, nil
}

// Run reconciles all assigned secret.read grants into a dedicated private
// directory. Any refresh failure removes the files; no offline cache is kept.
func (c *Client) Run(ctx context.Context, dir string, interval time.Duration, report func(error)) error {
	if interval < time.Second || interval > time.Hour {
		return errors.New("poll interval must be 1s..1h")
	}
	r, err := privateRoot(dir)
	if err != nil {
		return err
	}
	defer r.Close()
	unlock, err := Lock(dir)
	if err != nil {
		return err
	}
	defer unlock()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	marker := c.state.Server + "\n" + c.state.AccountID + "\n" + c.state.DeviceID + "\n"
	markerFile, err := r.Open(".secretserver-agent")
	if os.IsNotExist(err) {
		if len(entries) != 1 || entries[0].Name() != ".lock" {
			return errors.New("output directory must be empty on first use")
		}
		if err = atomicWrite(r, ".secretserver-agent", []byte(marker)); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		var got [4096]byte
		n, e := markerFile.Read(got[:])
		markerFile.Close()
		if e != nil || string(got[:n]) != marker {
			return errors.New("output directory belongs to a different agent")
		}
	}
	clean := func(keep map[string]bool) error {
		dirFile, err := r.Open(".")
		if err != nil {
			return err
		}
		entries, err := dirFile.ReadDir(-1)
		dirFile.Close()
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if (strings.HasSuffix(entry.Name(), ".json") || strings.HasPrefix(entry.Name(), ".tmp-")) && !keep[entry.Name()] {
				if err := r.Remove(entry.Name()); err != nil {
					return errors.New("cannot remove stale secret output")
				}
			}
		}
		return nil
	}
	// On a restart, remove previous-process material before any network call.
	if err = clean(nil); err != nil {
		return err
	}
	defer func() {
		if e := clean(nil); e != nil && report != nil {
			report(e)
		}
	}()
	for {
		cycle := func() error {
			ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			identity, err := c.Identity(ctx)
			if err != nil {
				return err
			}
			keep := map[string]bool{}
			values := map[string][]byte{}
			for _, grant := range identity.Grants {
				if grant.Service != "secret.read" && grant.Service != "variable.resolve" {
					continue
				}
				raw, err := c.Access(ctx, grant.Alias, []byte("{}"))
				if err != nil {
					return err
				}
				var response struct {
					Data map[string]string `json:"data"`
				}
				if json.Unmarshal(raw, &response) != nil || response.Data == nil {
					return errors.New("invalid secret response")
				}
				value, _ := json.Marshal(response.Data)
				name := grant.Alias + ".json"
				values[name] = append(value, '\n')
				keep[name] = true
			}
			if err = clean(keep); err != nil {
				return err
			}
			for name, value := range values {
				if err = atomicWrite(r, name, value); err != nil {
					return errors.New("cannot write secret output")
				}
			}
			return nil
		}
		if err = cycle(); err != nil {
			if e := clean(nil); e != nil {
				return e
			}
			if report != nil {
				report(err)
			}
			var httpErr *HTTPError
			if errors.As(err, &httpErr) && (httpErr.Status == 401 || httpErr.Status == 403) {
				return err
			}
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
