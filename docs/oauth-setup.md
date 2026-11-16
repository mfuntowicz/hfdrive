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
Automatic onboarding returns to the normal shell if a later accepted status
reveals an existing drive; an explicitly opened **Add drive** form stays open.

For development, build through `scripts/build.ps1` (or initialize
`scripts/Initialize-BuildEnvironment.ps1` before Cargo). The provider embeds
the exact trusted desktop executable path at build time; plain Cargo without
that environment does not authorize a development desktop.

Setup has no system title bar or minimize/maximize buttons. Drag the blank top
strip to move it; the single top-right close icon hides setup to the tray without
discarding the wizard or stopping the provider. Finishing setup or choosing
**Back to HF Drive** restores the normal application's standard window controls.
**Open HF Drive** reopens the current surface, including an unfinished setup;
explicit account, connection, and issue actions still navigate to their pages.

1. **Sign in** — request bucket read access through Hugging Face. Device sign-in
   remains an explicit alternative. An already signed-in account skips this page.
2. **Bucket** — choose the account/organization, bucket, and new or existing drive.
   Optional private-bucket creation and the exact managed location have expandable
   details. If the current grant lacks `manage-repos`, Create private bucket starts
   an explicit re-consent instead of submitting the creation, scoped to the selected
   organization when applicable; the user then retries after consent. Creation and
   consent failures appear beside that button and scroll into view. Continue
   inspects the location without creating remote objects.
3. **Folder & access** — use the native folder picker or edit the suggested
   unused `%USERPROFILE%\HF Drive\<bucket>` path. Occupied names receive a numeric
   suffix; entered paths and the same bucket's prior suggestion are preserved.
   Two-way sync explicitly requests write
   permission and separately protects the storage access keys. Check & review
   reserves setup, runs the real storage checks, and builds the persisted preview.
   Browse-only skips publication keys and probes. Failed checks never enable writes.
4. **Review** — confirm bucket/location, local folder, access mode, new-workspace
   initialization, and any collision actions before connecting. A changed preview
   must be reviewed again. Successful setup stays visible until Open HF Drive.

An existing drive's registered folder belongs to that connection. Manage it
through **Connections**; a new setup must use another folder rather than taking
over the existing registration. Root validation reports its specific filesystem
rejection instead of replacing every failure with a generic invalid-root message.

The form uses CatchingHuggy artwork with the same default Mica-aware Fluent
cards, footer, actions, and native theme controls as Settings. Technical identifiers
and probe results stay expandable, including failed checks before review. Secret
fields are cleared before any asynchronous submission; immutable .NET strings
still cannot be guaranteed erased. No local “setup complete” flag overrides
provider state, and resetting the form never deletes durable setup or user data.

After Connect succeeds, `HuggyPop.gif` celebrates only while the provider reports
that new drive as usable and working. A probe or preview alone never triggers it.
The animation stops when setup is hidden or Windows animations are disabled.

## Desktop tray

CatchingHuggy identifies the app, taskbar, package, and notification-area icon.
Selecting the tray icon opens a compact native panel at the taskbar's work-area
corner; Escape or deactivation dismisses it. Closing the main window keeps the
tray and provider connection alive. The tray menu distinguishes exiting the
desktop UI from the separately confirmed provider exit.

Setup and the tray panel share [Windows 11's native rounded-corner policy](https://learn.microsoft.com/en-us/windows/apps/desktop/modernize/ui/apply-rounded-corners)
without a white nonclient frame. Corners are composed by Windows, not simulated
with window regions or per-pixel transparency; Windows may suppress rounding
when a window is snapped, maximized, or subject to its virtualization policy.

The panel reads current per-file activity, paged operation history, and conflicts
from the authenticated provider. Drive selection, Open folder, pause/resume, and
issue navigation use the same application session. Unsupported activity,
disconnection, loading, and failures are not treated as an empty queue.
Connection errors and failed activity/history/conflict requests appear under
**Issues**. An empty queue while syncing is blocked is not shown as healthy.
Each request retains its own error until a fresh successful response; an older
page response cannot clear a newer authorization failure. Storage-access actions
manage the existing connection rather than opening **Add drive**.
Equal-width **Syncing now** and **Recent activity** tabs present their contents
in separate cards, keeping **Issues** visible below. Syncing shows a green check
and “Everything is up to date” only when the provider proves all synced; blocked,
unknown, or failed states retain their actual status instead.

The header shows only the HF Drive title. The signed-in profile picture comes
from verified OIDC userinfo's `picture` claim, is restricted to HTTPS Hugging
Face hosts, and loads without bearer credentials; CatchingHuggy is the loading,
missing, or failed-image fallback. It occupies the left identity slot beside the
centered Inter-font HF Drive title; Refresh/Close remain on the right.

`VibingHuggy.gif` appears at the top of the body only when every configured
drive has fresh, healthy, up-to-date status and a proven empty activity queue.
No drives, pending work, paused or failed drives, conflicts, or stale status
qualify. Each continuous all-synced state plays the 121-frame, 40 ms GIF exactly
twice (9.68 seconds total). Routine status refreshes do not restart it; hiding
the panel or disabling animations pauses it and preserves the remaining budget.
The footer has equal-width Pause/Add/Open actions. The Add bucket button has
an HF yellow background and dark plus glyph; it opens the existing bucket setup
only and never creates storage or starts consent by itself.

## Desktop settings

Launching the desktop creates only the tray icon; it does not open Settings or
setup. Provider startup still runs independently of window visibility. The tray
menu's **Settings** action opens that page explicitly; **Open HF Drive** reopens
whichever page or unfinished setup was already active. CatchingHuggy and native
rounded corners match onboarding and
the tray. MainWindow scopes its transparent surfaces to its own Mica backdrop;
the tray retains its opaque HF background, header, cards, and Huggy branding.
Settings cards, inputs, expanders, and actions use the default Mica-aware
Fluent brushes rather than custom navy fills. Left navigation selection and
hover surfaces are rectangular. Windows/WinUI owns focus, accent, and high
contrast colors. The configured window keeps resize and standard window
controls in a theme-integrated caption.

**Transfer speeds** contains upload and download limits. Enter `Unlimited` or
`0` for no limit, an exact byte count, or an IEC quantity such as `10 MiB/s`.
**Local storage** contains transfer memory, range cache, staging admission, and
the free-space reserve; quantities such as `512 MiB` and `10 GiB` are accepted.
Decimal quantities must resolve to whole bytes. Leaving a field empty preserves
its stored value; displaying or saving another field never rounds that value.

Values load from the provider before editing is enabled. **Save settings**
submits only changed values against the observed revision. **Reload settings**
refreshes the provider state while preserving an unsaved draft; **Discard my
changes** asks for confirmation before replacing it. A revision conflict keeps
the draft for review instead of silently retrying or overwriting another client.
The clean loaded state has no footer status text; unsaved drafts, successful
saves, preserved-draft reloads, and errors still report their status.

**Account** contains sign-in, owners, and expandable provider details.
**Connections** shows the actual drive health and local folders. UUID-scoped
sync controls, selective sync, history, restore, conflicts, and diagnostics remain
available under **Advanced**. These pages share the existing provider session;
opening settings never recreates a drive or changes its storage binding.


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

### Repair an existing drive

To reuse keys already protected by a successful setup for the same account and
bucket, keep the existing connection and use the source setup's proposed
connection ID:

```powershell
hfdrive repair-storage --connection <existing-connection-id> --credentials-from <verified-source-connection-id>
```

The provider verifies the existing workspace and root, runs fresh storage checks,
and replaces only the existing connection's credential binding. It does not
initialize a workspace, change the folder, unregister the drive, discard local
work, or consume the source credentials. The durable paused intent is preserved.
Keys never appear in command arguments.

An incomplete repair exits nonzero and reports the resulting status. A failure
after credential adoption retains the adopted protected record rather than
leaving a dangling credential reference; do not reset or add another drive to
retry recovery.

## Browser launch boundary

The system browser is opened with one validated `https` URL passed as a
single OS argument (`ShellExecuteW`, operation `open`). No shell command
line is built and no string interpolation happens.
