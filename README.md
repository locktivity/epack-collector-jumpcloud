# epack-collector-jumpcloud

Collects JumpCloud identity, access, and device posture metrics for evidence packs.

## What it collects

Every run emits one detailed artifact:

- `artifacts/jumpcloud.json`: JumpCloud-specific posture

When user discovery is complete (not capped), a second normalized artifact is also emitted:

- `artifacts/jumpcloud.idp-posture.json`: normalized `evidencepack/idp-posture@v1` posture

The IDP artifact is omitted when user discovery is incomplete or there are no users, because percentages computed from a partial population would misrepresent actual coverage.

When device discovery succeeds, a normalized endpoint artifact is also emitted, independent of user discovery:

- `artifacts/jumpcloud.endpoint-posture.json`: normalized `evidencepack/endpoint-posture@v1` posture

### Endpoint posture

Every percentage is `passing / (passing + failing)` over in-scope devices, with a `metric_coverage` entry giving passing, failing, unknown, and not-applicable device counts. Unknown readings are never counted as passing or failing. When a metric cannot be measured, it is omitted and `availability` says why.

| Control | Source | Pass | Fail |
|---------|--------|------|------|
| Disk encryption (Windows) | System Insights `bitlocker_info`, every volume | Every volume has protection on and is fully encrypted | Every volume has protection off (including suspended) or is not fully encrypted |
| Disk encryption (other OSes) | Agent `fde.active` on `/api/systems` | `true` | `false` |
| Firewall (macOS) | System Insights `alf` | `global_state` 1 or 2 | `global_state` 0 |
| Firewall (Windows) | System Insights `windows_security_center` | `Good` | `Poor` |
| Antimalware installed (Windows) | System Insights `windows_security_products` | An antivirus product is registered | A fresh, fully classified product list has no antivirus product |
| Antimalware healthy (Windows) | System Insights `windows_security_products` | An antivirus product is on with current signatures | Every antivirus product is off, snoozed, expired, or has outdated signatures, and every product is classified |

Readings older than `max_observation_age_hours` (default 168) are unknown. `fde.active` has no observation time, so it is only accepted from devices whose last agent check-in is within the limit, and no `observed_at` is reported for it. On Windows, a fresh `fde.active=false` is used as a failure when there is no fresh BitLocker reading.

Not measured, and always listed in `availability`: screen lock, EDR, OS support and patch baselines, and overall compliance. Firewall and antimalware on Linux and mobile devices are reported as unknown.

Anything else is unknown: unrecognized or "Unknown" states, products without a recognized type, Windows devices whose volumes disagree (BitLocker does not say which volume holds Windows), and every reading from a System Insights table that hit the row cap. Duplicate device records resolve to the one with the newest `lastContact`; equally fresh records that disagree make the affected readings unknown, and a disagreement on OS makes every control for that device unknown. A device with any local account missing its admin flag has no `local_admin_accounts` list.

When device discovery is incomplete, fleet totals, percentages, and coverage are omitted, `scope.discovery_complete` is `false`, and each metric is listed as `partial`.

### Collection levels

Set the collection level with the `level` config key (default `trust`). This controls what data is gathered and how much detail is disclosed.

| Surface | Trust | Audit | Internal |
|---------|-------|-------|----------|
| User counts and MFA adoption percentages | Yes | Yes | Yes |
| Admin counts, TOTP enrollment, and MFA requirement | Yes | Yes | Yes |
| SSO app counts and coverage | Yes | Yes | Yes |
| Authentication policy configuration summary | Yes | Yes | Yes |
| Device/system counts, OS breakdown, MDM enrollment | Yes | Yes | Yes |
| Per-user inventory (username, email, state, MFA status) | | Yes | Yes |
| Per-app inventory (name, SSO type) | | Yes | Yes |
| User and system group inventory | | Yes | Yes |
| Per-device inventory (hostname, OS, agent, MDM) | | Yes | Yes |
| Per-policy inventory (name, type, MFA factors, conditions) | | Yes | Yes |
| Directory Insights audit events (7-day window) | | | Yes |
| Endpoint posture: fleet counts, control percentages, coverage | Yes | Yes | Yes |
| Endpoint posture: per-device controls, primary user, last seen | | Yes | Yes |
| Endpoint posture: local administrator accounts per device | | | Yes |

### What it does not measure

- **Login activity / inactivity**: the collector does not query per-user login timestamps, so `inactive_pct` is not emitted in the normalized artifact.
- **Administrator MFA beyond TOTP**: JumpCloud's admin API reports TOTP enrollment and whether MFA is required, but not other factors such as security keys. The detailed artifact reports both separately, and the IDP artifact sets `privileged_mfa_coverage_pct` only when every administrator has TOTP enrolled.
- **Effective policy enforcement**: the detailed artifact describes policy *configuration* (which policies exist, what they require). It does not evaluate effective enforcement across targets, monitoring mode, or fallback behavior. The normalized artifact omits policy and device-access claims for this reason.
- **Complete event history**: audit event counts at the internal level summarize the fetched sample (capped at 5,000 rows). They are not necessarily complete seven-day totals.

### Incomplete discovery

Each paginated API surface has an internal safety cap (50,000 rows). When discovery is capped:

- V1 surfaces (users, apps, admins, systems) report `partial: true` in their metrics and the server-reported total is preserved where available.
- V2 surfaces (groups, policies) emit a diagnostic warning when capped.
- The normalized artifact is omitted entirely when user discovery is partial.

## Quick start

1. Install the epack CLI: `brew install locktivity/tap/epack`.
2. Create a JumpCloud API key. A read-only service account is recommended; see [Authentication](#authentication).
3. In an empty directory, save this as `epack.yaml`:

   ```yaml
   stream: example/jumpcloud-posture

   collectors:
     jumpcloud:
       source: locktivity/epack-collector-jumpcloud@^0.1
       config:
         level: trust  # trust, audit, or internal
       secrets:
         - JUMPCLOUD_API_KEY
   ```

   `collectors` is a mapping keyed by collector name. `secrets` lists the names of environment variables to pass to the collector, never their values.

4. Run the collection. `read -rs` keeps the key out of your shell history:

   ```bash
   read -rs JUMPCLOUD_API_KEY && export JUMPCLOUD_API_KEY
   epack lock
   epack collect
   ```

   `epack lock` resolves and pins the collector release in `epack.lock.yaml`. `epack collect` writes an `evidence-<timestamp>.epack` file containing `artifacts/jumpcloud.json`, `artifacts/jumpcloud.idp-posture.json`, and `artifacts/jumpcloud.endpoint-posture.json`. Inspect it with `epack inspect <file>`.

### Running a local build

To run a binary you built instead of a published release, replace `source` with `binary`. The path must be absolute:

```bash
make build
```

```yaml
stream: example/jumpcloud-posture

collectors:
  jumpcloud:
    binary: /absolute/path/to/epack-collector-jumpcloud
    config:
      level: trust
    secrets:
      - JUMPCLOUD_API_KEY
```

Then run `epack lock` and `epack collect` as above.

## Configuration

| Key | Required | Description |
|-----|----------|-------------|
| `level` | No | Collection detail: `trust`, `audit`, or `internal`. See [Collection levels](#collection-levels). |
| `org_id` | No | JumpCloud organization ID (string). Required for MSP/multi-tenant setups where the API key has access to multiple organizations. Must be a string; a non-string value is rejected. |
| `max_observation_age_hours` | No | How old device telemetry may be and still count as a current reading. Whole number from 1 to 8760. Default 168 (7 days). |

When `org_id` is set, the collector validates it against the organization list. When unset and the API key returns multiple organizations, collection fails with a clear error.

## Authentication

Set `JUMPCLOUD_API_KEY` to a JumpCloud API key. Either kind works; both are sent in the `x-api-key` header.

- **Service account (recommended):** in the Admin Portal, go to Settings > Service Accounts > + New, choose the Read Only role, and select API keys as the key type. The key is not tied to any one administrator. Service accounts cannot read `/api/organizations`, so the detailed artifact omits `org_id` and records a warning. Service accounts are not available to MSP organizations.
- **Personal API key:** click your account name in the bottom-left of the Admin Portal and choose My API Key. API access must first be enabled by an Administrator with Billing. Generating a new key revokes the previous one, and the key carries that administrator's full permissions.

### Required permissions

The API key needs read access to:
- System users (`/api/systemusers`)
- Applications (`/api/applications`)
- Organizations (`/api/organizations`, optional)
- Admin Portal administrators (`/api/users`)
- Systems (`/api/systems`)
- User groups and system groups (`/api/v2/usergroups`, `/api/v2/systemgroups`)
- Authentication policies (`/api/v2/authn/policies`)
- Directory Insights events at internal level (`/insights/directory/v1/events` on `api.jumpcloud.com`)
- System Insights tables, requested only for OS families present in the fleet (`/api/v2/systeminsights/bitlocker_info`, `windows_security_center`, `windows_security_products`, `alf`, and `users` at internal level). System Insights must be enabled for the organization.

Surfaces that return 403 degrade gracefully: that section is omitted and a diagnostic is recorded. A denied System Insights table makes the affected endpoint controls unknown with a `permission_denied` availability entry. A 401 from any surface is fatal.

### Service hosts

The collector contacts two JumpCloud API hosts:
- `console.jumpcloud.com` for V1/V2 management APIs
- `api.jumpcloud.com` for Directory Insights

Regional endpoints are not currently supported.

## Development

```bash
make build       # build for current platform
make test        # run unit tests
make lint        # golangci-lint + forbidden-data check
make e2e         # run e2e tests (requires JUMPCLOUD_API_KEY)
make sdk-test    # run via epack SDK test harness
make sdk-run     # run via epack SDK
```

## Release

Tag a version to trigger the release workflow:

```bash
git tag v0.1.0
git push origin v0.1.0
```

Builds are produced with SLSA Level 3 provenance for linux/darwin on amd64/arm64.
