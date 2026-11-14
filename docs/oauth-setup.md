# HF Drive OAuth setup

HF Drive signs in with its **own public OAuth client**. There is no shared,
borrowed or bundled client id and no client secret anywhere in the product.

## Registering the product client

1. Sign in at <https://huggingface.co> and open
   <https://huggingface.co/settings/applications/new>.
2. Register a **public** client (no client secret) with the exact callback
   URL `http://127.0.0.1/oauth/callback`.
3. Set the issued client id in the provider's environment:

   ```powershell
   $env:HFDRIVE_OAUTH_CLIENT_ID = "<the client id you registered>"
   ```

The provider binds its callback listener to `127.0.0.1:0` at login time and
launches the system browser; only the port differs from the registered URL.
There is no wildcard binding, no `localhost` DNS name, no embedded WebView
and no alternate callback path.

### Missing configuration is a hard gate

If `HFDRIVE_OAUTH_CLIENT_ID` is absent or blank at startup, every login fails
with `OAuthClientNotConfigured` and nothing is sent to any server. No
placeholder or sample client id is ever substituted, in any build.

## Desktop onboarding

HF Drive opens a compact, four-step WinUI window when the authenticated provider
reports no configured drives. It also returns to setup when the last drive is
removed. Startup connects to the existing provider or starts the exact trusted
provider image; connection failure shows Retry, not an invented empty setup.
Configured users go directly to the normal application. Adding another drive
opens the same compact form without deleting existing connections or local files.

1. **Sign in** — request bucket read access through Hugging Face. Device sign-in
   remains an explicit alternative. An already signed-in account skips this page.
2. **Bucket** — choose the account/organization, bucket, and new or existing drive.
   Optional private-bucket creation and the exact managed location have expandable
   details. Continue inspects the location without creating remote objects.
3. **Folder & access** — use the native folder picker or edit the suggested
   `%USERPROFILE%\HF Drive\<bucket>` path. Two-way sync explicitly requests write
   permission and separately protects the storage access keys. Check & review
   reserves setup, runs the real storage checks, and builds the persisted preview.
   Browse-only skips publication keys and probes. Failed checks never enable writes.
4. **Review** — confirm bucket/location, local folder, access mode, new-workspace
   initialization, and any collision actions before connecting. A changed preview
   must be reviewed again. Successful setup stays visible until Open HF Drive.

The form uses the official Hugging Face graphic and Storage-inspired blue/neutral
resources with native light, dark, and high-contrast controls. Technical identifiers
and probe results stay expandable, including failed checks before review. Secret
fields are cleared before any asynchronous submission; immutable .NET strings
still cannot be guaranteed erased. No local “setup complete” flag overrides
provider state, and resetting the form never deletes durable setup or user data.


## Flows

### PKCE (default)

* Authorization-code flow with PKCE S256; 32 random bytes each (OS CSPRNG)
  for `state`, `nonce` and the PKCE verifier.
* Exactly one login may be outstanding; the session expires after 5 minutes.
* The callback accepts only `GET` on the exact path and loopback
  host:port, rejects duplicate parameters, oversized requests (16 KiB
  bound), wrong methods/paths/hosts and mismatched `state` (constant-time
  comparison) without consuming the valid attempt. The valid success or
  denial is consumed exactly once; a duplicate callback can never exchange
  the code twice.
* ID tokens are validated for RS256 signature, issuer, audience, expiry and
  nonce; the userinfo subject must agree with the ID token subject. Access
  tokens — never ID tokens — authorize API calls.

### Device flow (explicit fallback only)

* Selecting `--device` (or the UI equivalent) uses the provider's device
  authorization endpoint. Device login is **never** started automatically
  after a browser failure; the browser-flow failure is reported instead.
* Polling honors the server `interval` (5 s when omitted) and adds 5 s on
  `slow_down`; `access_denied`/`expired_token` end the session immediately.
* If the live device grant cannot prove the requested storage purpose, the
  login fails and a PKCE re-consent is required — access is never pretended.

## Scopes (incremental consent)

| Purpose         | Requested scopes                                          |
|-----------------|-----------------------------------------------------------|
| `signin`        | `openid profile read-memberships`                          |
| `read_storage`  | `openid profile read-memberships read-repos`               |
| `write_storage` | `openid profile read-memberships read-repos write-repos`   |
| `create_storage`| `openid profile read-memberships read-repos write-repos manage-repos` |

* Only explicit creation adds `manage-repos`. No `*-buckets` or
  `offline_access` scope is ever requested.
* An organization re-consent passes exactly one `orgIds=<orgs[].sub>`
  parameter with the **verified organization subject** from userinfo. A
  login for an organization that is not in the verified identity fails with
  `OrganizationNotVerified`.
* A granted scope list the provider omits is recorded as *unknown*, not as
  proven empty.
* The personal namespace (`preferred_username`) must validate as a canonical
  HF namespace or the identity is rejected — HF Drive never invents a
  namespace from the subject. Organization display names are optional
  display hints.

## Credential storage and refresh

* Tokens live in a user-scoped DPAPI-protected envelope
  (`accounts/<account>/credentials/oauth.hfdcred`, `credential_ref` in the
  state database is that exact file name) outside all sync roots. They are
  never logged, never sent over IPC and never placed in argv.
* The envelope is replaced atomically **before** a rotated token is exposed.
* Refresh runs at the earlier of five minutes before expiry and 10% of the
  token lifetime, single-flight per account; a rotation that omits a
  replacement refresh token retains the previous one. `invalid_grant` fails
  closed to `NeedsSignIn` — there is no refresh retry loop.
* Credential generations rotate on refresh and are distinct from the
  authorization epoch: refreshing can never revive a lease invalidated by
  sign-out.
* Sign-out cancels any pending login (a late callback cannot activate),
  revokes the authorization epoch, and removes the usable session secrets
  while local work stays untouched.

## Supplemental S3 publication keys are separate

Managed publication uses **separate S3 credentials** generated through HF
token settings (<https://huggingface.co/docs/hub/storage-buckets-s3>). They
are entered in the dedicated setup form, protected separately, and are never
an OAuth replacement: a PAT is never accepted as an OAuth token, and the key
pair does not prove the OAuth person's identity. Their scope may cover the
whole bucket.

## Browser launch boundary

The system browser is opened with one validated `https` URL passed as a
single OS argument (`ShellExecuteW`, operation `open`). No shell command
line is built and no string interpolation happens.
