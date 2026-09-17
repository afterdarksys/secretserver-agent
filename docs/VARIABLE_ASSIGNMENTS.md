# Named secret variables

Map a stable name such as `LOG_SERVER_TX1_S` to an existing credential's field,
then resolve `%%LOG_SERVER_TX1_S%%` when a playbook, application, or build needs
it. Assignments contain references, never copied passwords. Rotation changes the
next resolved value without editing templates.

## Create an assignment

Use **Secret Variables** in the web dashboard, the desktop client's Variables
tab, an SDK, Terraform, or the CLI:

```sh
# A root_credential stores its password under the password field:
ss variables assign LOG_SERVER_TX1_S root_credential CREDENTIAL_UUID password
# A password record uses the value field instead:
ss variables assign LOG_SERVER_TX1_S password PASSWORD_UUID value
```

Account-admin access is required to create, list, update, or delete mappings.
Credential IDs must belong to that account. The field is a literal top-level
Vault data key, not a JSONPath expression. The credential must already exist;
a missing/non-string field causes resolution to fail. The dashboard shows only
assignment metadata. Assignment IDs are stable across updates, but deleting and
recreating an assignment gives it a new ID.

Supported target types are the platform's path-addressable credentials: `secret`,
`password`, `api_token`, `certificate`, `ssh_key`, `gpg_key`, `openssl_key`,
`ntlm_hash`, `computer_credential`, `wifi_credential`, `windows_credential`,
`social_credential`, `disk_credential`, `service_config_credential`,
`root_credential`, `ldap_bind_credential`, `integration_credential`, and
`code_signing_key`. Non-exportable HSM keys remain operation-only; a variable
cannot turn a signing key into downloadable private material.

## Resolution contract

- Names match `[A-Z_][A-Z0-9_]{0,127}` and are case-sensitive/account-scoped.
- `%%NAME%%` resolves the current string field. Empty strings are valid.
- `%%%%` escapes a literal `%%` (for example `%%%%NAME%%%%` becomes `%%NAME%%`).
- Expansion is single-pass. Inserted passwords are never scanned for more tokens.
- Missing variables, denied permissions, missing fields, invalid syntax, expired
  generic secrets, and expired/revoked API tokens fail the whole request. No
  partial output or unresolved fallback is returned.
- Repeated references to a name use one value within a request. Reads of different
  variables are not a transactional snapshot of all Vault secrets.
- Maximum request body: 1 MiB; maximum encoded response: 4 MiB; maximum distinct
  variable references: 256; maximum document nesting: 64 levels.
- Responses are `Cache-Control: no-store`; audit events identify assignments and
  credential references, never templates or resolved values.

API-key/OAuth callers must retain the underlying credential read permission (or
an applicable resource share). Key exports additionally require `export:read`,
just as ordinary material access does. Knowing a variable name grants no access.

## REST API

| Method | Endpoint | Result |
| --- | --- | --- |
| PUT | `/api/v1/variables/{NAME}` | Assign/update `{secret_type, secret_id, field}` |
| GET | `/api/v1/variables/{NAME}` | Mapping metadata |
| GET | `/api/v1/variables` | `{variables: [...]}`; up to 1,000 mappings |
| DELETE | `/api/v1/variables/{NAME}` | Delete mapping; 204 |
| POST | `/api/v1/variables/resolve` | Resolve text or a JSON document |

Text request and response:

```json
{"template":"sudo_password=%%LOG_SERVER_TX1_S%%"}
```

```json
{"rendered":"sudo_password=resolved-value","variables":["LOG_SERVER_TX1_S"]}
```

For structured configuration, send `{"document":{"password":"%%LOG_SERVER_TX1_S%%","port":443}}`.
The response has `document` and `variables`. Only string **values** are processed;
object keys, booleans, numbers, null, and structure are preserved. Quotes and
newlines in passwords are encoded as JSON data. Raw text rendering does not
escape shell, YAML, SQL, HCL, or other syntax—prefer structured resolution or a
consumer's native variable input when generating configuration.

## Ansible

Both the collection lookup and standalone client lookup recognize tokens:

```yaml
- name: Configure log server
  hosts: log_servers
  become: true
  vars:
    ansible_become_password: "{{ lookup('afterdark.secretserver.secretserver', '%%LOG_SERVER_TX1_S%%') }}"
  tasks:
    - name: Configure protected service
      ansible.builtin.file:
        path: /etc/log-service
        state: directory
        mode: '0750'
      no_log: true
```

Supply `SS_API_KEY`/`SS_API_URL` or the plugin's `api_key`/`api_url` options. For the
standalone lookup use `lookup('secretserver', ...)`. `render=true` treats a term
as a template even if it has no tokens. Existing path lookups continue to work.
Use `no_log: true` on tasks consuming secret results. Do not enable unsafe lookup
re-templating or debug secret values. Merely placing `%%NAME%%` in arbitrary
Ansible YAML does not activate substitution: invoke the lookup processor.

## Terraform

`secretserver_variable` stores only assignment metadata in state:

```hcl
resource "secretserver_variable" "sudo" {
  name        = "LOG_SERVER_TX1_S"
  secret_type = "root_credential"
  secret_id   = var.root_credential_id
  field       = "password"
}

ephemeral "secretserver_template" "sudo" {
  template   = "%%LOG_SERVER_TX1_S%%"
  depends_on = [secretserver_variable.sudo]
}
```

Use `ephemeral.secretserver_template.sudo.value` only in contexts Terraform
allows for ephemeral values, such as compatible provider configuration or
write-only resource arguments. This requires Terraform 1.10+; write-only resource
arguments require a compatible Terraform/provider version. There is deliberately
no ordinary secret-template data source: `sensitive` alone would not keep values
out of state. Import an assignment by its **name**.

## SDKs and build processing

| Consumer | Assign | Resolve text | Resolve JSON values |
| --- | --- | --- | --- |
| Go public SDK and server SDK | `AssignVariable` | `Render(ctx, text)` | `ResolveDocument(ctx, json.RawMessage)` |
| Python | `assign_variable` | `render(text)` | `resolve_document(document)` |
| Node/TypeScript | `assignVariable` | `render(text)` | `resolveDocument(document)` |
| PHP | `assignVariable` | `render(text)` | `resolveDocument(document)` |
| CLI | `ss variables assign` | `ss render file` | `ss render --json file` |
| Agent | Admin assigns profile grants | `secretserver-agent render --input file` | add `--json` |
| Desktop GUI | Variables tab | Explicit Resolve template button | Use Go SDK |
| MCP bridge | Admin REST/SDK | opt-in `resolve_secret_template` tool | Use REST/SDK |

PHP `resolveDocument` returns JSON objects as `stdClass` and JSON arrays as PHP
arrays, preserving empty objects and numeric-key objects at every nesting level.

All four SDKs also expose list/get/delete assignment methods. Calls fail rather
than return an unresolved template. SDK operations do not silently process every
string in every API request; resolution is an explicit step.

For a build that genuinely needs a generated file, choose a private output:

```sh
umask 077
ss render --json application.template.json > application.private.json
# Or with enrolled device authentication:
secretserver-agent render --json --input application.template.json > application.private.json
```

Rendered output contains plaintext secrets. Keep it out of source control, build
logs, caches, published images, and distributable artifacts. Prefer runtime
injection for services. A failed command emits no rendered content, although
shell redirection may have created/truncated the destination; use a temporary
file and rename on success if replacing a live configuration.

## Agent grants

An admin adds a profile grant referencing the mapping's UUID:

```json
{"alias":"sudo-password","service":"variable.resolve","resource":"VARIABLE_UUID"}
```

The device can resolve only these assigned variable IDs through signed
`POST /api/v1/agent/variables/resolve` requests. An underlying `secret.read` grant
alone does not authorize every alias to that secret. `access --alias sudo-password`
returns `{data:{value:...}}`. The agent refresh loop automatically writes such
grants to private `<alias>.json` files alongside its ordinary secret grants.
An admin retargeting an assigned variable intentionally updates future device
access. Removed mappings/grants or device/profile revocation stop future access.

MCP resolution is disabled by default. Enabling
`SECRETSERVER_ENABLE_SECRET_RESOLUTION=1` registers a tool whose plaintext result
enters model context. The operation-only signing tools remain unchanged.

## Installation and verification

Deploy the matching server, client, provider, agent, and web changes together.
Fresh installs include `035_variables.sql` and the SSH metadata compatibility
fixes in `036_ssh_key_owner_contract.sql` and
`037_api_token_lifecycle_contract.sql`; API startup applies them idempotently
for existing installations. API names above describe the local implementation;
this work does not deploy or publish releases automatically.

Acceptance: verify tenant/type/export permissions, strict syntax, no partial
outputs, rotation, empty values, no recursive replacement, structured escaping,
agent grant isolation, real SDK/Ansible requests, Terraform ephemeral behavior,
and metadata-only persisted assignments. HSM crypto APIs do not parse templates;
resolution occurs in their consuming application if needed.

Primary references:
- https://developer.hashicorp.com/terraform/plugin/framework/ephemeral-resources
- https://developer.hashicorp.com/terraform/language/manage-sensitive-data
- https://docs.ansible.com/projects/ansible/latest/plugins/lookup.html
