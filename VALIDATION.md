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
this integration run. The sample systemd unit was not installed or executed.
