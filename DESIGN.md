# Device identity contract and review acceptance

User requirement: Go agent login with OAuth2 or API key; cryptographically verify
account/device binding and automatically apply exact key/service assignments.

Acceptance criteria:
- API-key and OAuth2 device enrollment bind the expected account, profile, device
  name, and public key. Read-only and foreign-account credentials cannot enroll.
- Only account admins can configure exact resource grants, with tenant ownership
  checked for every secret, signing key, and database role.
- Device requests prove possession of the enrolled key. A modified account,
  device, method, request URI, timestamp, nonce, or body must fail.
- Duplicate request nonces fail across API replicas, with database atomicity.
- A revoked device, disabled profile, inactive tenant, or removed grant cannot
  start new access. Signed-request credentials cannot access general admin APIs.
- OAuth codes expire, require explicit authenticated approval, enforce polling
  backoff, and return a single-use enrollment token tied to the initiating key.
- Agent verifies HTTPS, rejects redirects, verifies returned account/key/profile,
  and keeps bootstrap credentials out of persistent state and error logs.
- Private state and delivered files have restrictive permissions. Delivery uses
  atomic per-file writes and removes stale files on refresh failure or shutdown.
- Documentation states software-key cloning, crash, polling, in-flight access,
  and already-delivered secret limitations accurately.
- Integration tests use a real disposable database, Vault, HTTP API, and Go CLI.

## Cryptographic format

Ed25519 public keys and signatures use unpadded base64url. Enrollment signature:

```
secretserver-enroll-v1\nACCOUNT_UUID\nPROFILE_UUID\nNAME\nPUBLIC_KEY
```

Names are restricted to 1–128 ASCII letters, digits, dots, underscores and
hyphens, beginning with an alphanumeric character. Account/profile UUID strings
in the CLI are canonical lowercase.

Every resource request sends X-SecretServer-Account, X-SecretServer-Device,
X-SecretServer-Time (Unix seconds), X-SecretServer-Nonce (32 random bytes,
base64url), and X-SecretServer-Signature. Signed bytes:

```
secretserver-request-v1\nACCOUNT_UUID\nDEVICE_UUID\nMETHOD\nREQUEST_URI\nTIME\nNONCE\nSHA256_BODY_HEX
```

The server accepts at most 60 seconds of age and 5 seconds of future clock skew.
Successful verification consumes a `(device_id, nonce)` primary-key row before
any resource access. Nonces expire after two minutes, exceeding proof lifetime.
These versioned request signatures are a Secret Server protocol, not a claim of
DPoP or HTTP Message Signatures compliance. Server authenticity/account-binding
confidentiality comes from normal certificate-validated TLS; there is no custom
server signing certificate or hardware attestation protocol in this release.

OAuth device authorization uses RFC 8628 with fixed public client identifier
`secretserver-agent` and enrollment-binding extension parameters. Public endpoints:
`/api/v1/agent/oauth/device`, `/oauth/token`, `/oauth/enroll` (same prefix).
The short-lived OAuth bearer is useful only for enrollment; ongoing requests
always use device signatures and current server policy. Account enrollment is a
durable admin operation independent of the bootstrap credential's lifetime.

## Follow-up trust tier

Non-exportable device key interfaces for TPM 2.0, macOS Secure Enclave and Windows
CNG, with enrollment attestation validated against explicit account policy. Until
then, no physical-machine assurance or resistance to device-key copying is claimed.

Primary references:
- https://www.rfc-editor.org/rfc/rfc8628.html
- https://pkg.go.dev/crypto/ed25519
- https://pkg.go.dev/os#Root
- https://pkg.go.dev/net/http#Client
