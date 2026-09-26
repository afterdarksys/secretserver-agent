# Validation — 2026-09-17

Validated with matching server and web changes in the companion
`secretserver.io` repository. No production deployment or live account enrollment
was performed. Local build output: `bin/secretserver-agent`.

Passed:
- Agent: `go test -race ./...` and `go vet ./...`.
- Server: `go test -race ./internal/deviceauth ./internal/api/middleware ./internal/api/handlers ./internal/api`.
- Web: `./node_modules/.bin/tsc --noEmit`.
- Agent and API-server builds.
- `scripts/test-platform-integration.sh`: full platform suite and PostgreSQL
  backup/restore, including AgentEnrollmentAndAccess and real database credentials
  obtained through an enrolled device's assigned service grant.

Live integration exercised API-key enrollment, OAuth device approval/token
exchange, proof of possession, modified request rejection, sequential/concurrent
replay denial, tenant isolation, admin-route isolation, disabled profiles,
suspended accounts, grant removal, device revocation, OAuth denial and expiry,
real separate Go CLI login/status/read, real Vault secret retrieval, and issued
PostgreSQL credentials followed by server lease revocation.

An independent read-only security reviewer approved the final
scoped artifacts with no remaining confirmed security findings. The reviewer
reported an approval-page code-change race; the final version binds decisions to
an immutable reviewed code and disables edits while a request is pending.
Independent agent, proof, and limiter race tests passed. The final integration
run passed after reviewer approval.

Limits: browser approval UI type-checked and independently reviewed; an external
production OIDC provider/browser journey was not exercised. No physical TPM,
Secure Enclave, HSM, or production account was used. Agent `key.sign` dispatch
uses the existing signing service; actual hardware signing was not exercised by
this integration run. The sample systemd unit was not installed or executed in
that run (see the 2026-09-26 review below).

## Named-variable extension

The later named-variable implementation adds signed template/JSON resolution and
`variable.resolve` profile grants. Live tests passed for assigned-variable access,
unassigned-variable denial, and the separate agent CLI's JSON renderer. The final
cross-platform feature review was approved with no outstanding findings. See
[the variable guide](docs/VARIABLE_ASSIGNMENTS.md) for the shared contract.

## Production-readiness review — 2026-09-26

Local only: no production host, account, or `*.secretserver.io` endpoint was
contacted. Server code used: `secretserver.io` commit `086b727` (its `main`),
read-only.

Defects fixed on branch `prod-readiness-2026-09-26`, each with tests:

- Delivered aliases differing only in case (`DB`, `db`) wrote one file on
  case-insensitive filesystems, silently delivering one secret under the
  other's name. The refresh now fails closed.
- The HTTP client accepted TLS 1.2 (Go default). It now requires TLS 1.3 with
  normal certificate verification. Transport errors now include their cause
  (certificate, dial, redirect refusal) without request headers or bodies.
- The OAuth user code and verification URI were printed to the terminal
  unvalidated. Control characters and non-ASCII are now rejected.
- CLI: an unset `HOME` aborted every command even with `--state-dir`; `-h`
  exited 1; the output/state separation check compared path strings, missing
  nesting, symlinked ancestors, and case-insensitive spellings. It now compares
  file identity in both directions.
- systemd unit hardened (no capabilities, syscall filter, private devices and
  user namespace, W^X, restricted address families and more).

Evidence:

- `go vet ./...` clean; `go test -race -count=1 ./...` passes (`cmd` and
  `internal/agent`). New tests check the request and enrollment signatures
  against the server's canonical form and reject tampered account, device,
  method, URI, query, time, nonce, and body; expired proofs; wrong keys; and
  nonce reuse. They also cover enrollment and identity binding mismatches,
  traversal and duplicate aliases, unreflected server error bodies, oversized
  responses, OAuth device flow and unsafe responses, untrusted certificates,
  TLS 1.2 servers, fail-closed rendering, 0600 delivery, cleanup of stale files
  at restart before any network call, cleanup on failure and on shutdown, CLI
  exit codes, argument and input limits, and API-key login without persisting
  the key.
- Cross-compiled with `CGO_ENABLED=0` for linux/amd64, linux/arm64,
  darwin/arm64, darwin/amd64.
- `scripts/test-platform-integration.sh` equivalent: host SysV shared memory
  was exhausted, so PostgreSQL 16 ran in a disposable local Docker container;
  the same test and backup/restore steps passed, including
  `AgentEnrollmentAndAccess`, `VariableAssignments`, and the client SDK suites.
  A scratch-only extension additionally drove this CLI through OAuth device
  login (review and approve by an admin), signed access with the OAuth identity,
  `run` delivery of `secret.read` and `variable.resolve` grants, and device
  revocation stopping `run` and removing delivered files.
- systemd: `systemd-analyze verify` passed on Debian 12 (systemd 252) in a
  disposable container. The unit ran the agent against a local TLS 1.3 test
  server that checks proofs the same way the API does. Checked there: the
  documented service-account enrollment, 0600 delivery into
  `/run/secretserver-agent`, clean stop, SIGTERM cleanup by the agent, and exit
  after revocation with files removed. `systemd-analyze security` exposure is
  1.3 (was 7.4).

Not verified: the real API behind a production TLS terminator (the TLS 1.3 floor
assumes the deployment offers TLS 1.3), a browser OAuth approval journey,
hardware key storage, and physical macOS service installation.
Known limits kept by design: `.lock` survives a crash for operator inspection;
a revoked device under systemd retries every 15 seconds until disabled; state
writes are not followed by a directory fsync.
