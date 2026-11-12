# epack-collector-jumpcloud

Collects JumpCloud identity, access, and device posture metrics for evidence packs.

## What it collects

Every run emits one detailed artifact:

- `artifacts/jumpcloud.details.json`: JumpCloud-specific posture

It also emits a normalized identity artifact:

- `artifacts/jumpcloud.idp-posture.json`: normalized `evidencepack/idp-posture@v1` posture

Each section of the identity artifact comes from one list. A section is left out when its list was read only in part, because percentages over part of a population would misrepresent coverage. With no users, the percentages are null and `users_present` is false.

When the systems can be listed, a normalized endpoint artifact is also emitted, independent of user discovery:

- `artifacts/jumpcloud.endpoint-posture.json`: normalized `evidencepack/endpoint-posture@v1` posture

A value the collector cannot read is left out of these artifacts, with a gap in the collector result at `artifacts/jumpcloud.collector-result.json` that gives the reason.

### Endpoint posture

Every percentage is `passing / (passing + failing)` over in-scope devices, rounded down to a whole number. From the audit level, `metric_coverage` holds the passing, failing, unknown, and not-applicable device counts for each metric. Unknown readings are never counted as passing or failing. When a metric cannot be measured, it is omitted and `availability` says why. The detailed artifact's `device_controls` carries the same counts at every level, with percentages to two decimals.

| Control | Source | Pass | Fail |
|---------|--------|------|------|
| Disk encryption (Windows) | System Insights `bitlocker_info`, every volume | Every volume has protection on and is fully encrypted | Every volume has protection off (including suspended) or is not fully encrypted |
| Disk encryption (other OSes) | Agent `fde.active` on `/api/systems` | `true` | `false` |
| Firewall (macOS) | System Insights `alf` | `global_state` 1 or 2 | `global_state` 0 |
| Firewall (Windows) | System Insights `windows_security_center` | `Good` | `Poor` |
| Antimalware installed (Windows) | System Insights `windows_security_products` | An antivirus product is registered | A fresh, fully classified product list has no antivirus product |
| Antimalware healthy (Windows) | System Insights `windows_security_products` | An antivirus product is on with current signatures | Every antivirus product is off, snoozed, expired, or has outdated signatures, and every product is classified |

Readings older than `max_observation_age_hours` (default 168) are unknown. `fde.active` has no observation time, so it is only accepted from devices whose last agent check-in is within the limit, and no `observed_at` is reported for it. On Windows, a fresh `fde.active=false` is used as a failure when there is no fresh BitLocker reading.

Not measured, and always listed in `availability`: screen lock, EDR, OS support and patch baselines, and overall compliance. The table gives each one's gap in the collector result.

| Value | Gap code | Why |
|-------|----------|-----|
| `hardening.screen_lock_compliant_pct` | `not_read` | JumpCloud's Apple MDM device API (`/api/v2/applemdms/{id}/devices`) reports whether each Apple device's passcode meets its policy. The collector does not call it |
| `compliance.compliant_pct` | `not_read` | JumpCloud's Google EMM device API (`/api/v2/google-emm/devices/{id}`) reports whether each Android device complies with its policy. The collector does not call it |
| `patching.os_supported_pct` and `patching.unsupported_os_count` | `unsupported` | JumpCloud does not report whether an operating system version still gets security updates |
| `patching.os_baseline_compliant_pct` | `unsupported` | JumpCloud does not report whether an operating system meets a baseline |
| `protection.edr_installed_pct` and `edr_healthy_pct` | `unsupported` | JumpCloud does not report whether an EDR agent is installed or healthy |

Neither gap code makes a run partial. Each value's `availability` reason is the same as its gap code. A `not_read` value's message includes the API that reports it.

Firewall and antimalware on Linux and mobile devices are reported as unknown. When no device in the fleet has any reading for a control, its percentage is left out with an `unsupported` gap. Disk encryption is the exception when the fleet has a Mac or a Linux device. JumpCloud's System Insights `disk_encryption` table covers those, and the collector does not read it, so the gap is `not_read`. When System Insights has fresh readings for a control and none of them is a clear pass or fail, the percentage is left out and its `availability` reason is `source_error`.

Anything else is unknown: unrecognized or "Unknown" states, products without a recognized type, and Windows devices whose volumes disagree (BitLocker does not say which volume holds Windows). When a System Insights table fails or hits the row cap, each control that needs it is left out of the fleet figures and the device rows, with a gap. Duplicate device records resolve to the one with the newest `lastContact`; equally fresh records that disagree make the affected readings unknown, and a disagreement on OS makes every control for that device unknown. A device with any local account missing its admin flag has no `local_admin_accounts` list.

When device discovery is incomplete, fleet totals, percentages, and coverage are omitted, and each metric is listed as `partial`. `scope.discovery_complete` is then `false` when the collector's row limit stopped the systems list. It is `null` when the list ends before the total JumpCloud reported or lists a device twice, since the collector cannot tell whether a device is missing. The collector result then has an `invalid_response` gap on it.

### Collection levels

Set the collection level with the `level` config key (default `trust`). This controls what data is gathered and how much detail is disclosed.

| Surface | Trust | Audit | Internal |
|---------|-------|-------|----------|
| User counts and MFA adoption percentages | Yes | Yes | Yes |
| Admin counts, TOTP enrollment, and MFA requirement | Yes | Yes | Yes |
| SSO app counts and coverage | Yes | Yes | Yes |
| Authentication policy configuration summary | Yes | Yes | Yes |
| Device/system counts, OS breakdown, MDM enrollment | Yes | Yes | Yes |
| Device controls (encryption, firewall, antimalware): percentage with passing, failing, unknown, and not-applicable device counts | Yes | Yes | Yes |
| Per-user inventory (username, email, state, MFA status) | | Yes | Yes |
| Per-app inventory (name, SSO type) | | Yes | Yes |
| User and system group inventory | | Yes | Yes |
| Per-device inventory (device ID, hostname, OS, agent, MDM, control states) | | Yes | Yes |
| Per-policy inventory (name, type, MFA factors, conditions) | | Yes | Yes |
| Directory Insights audit events (7-day window) | | | Yes |
| Endpoint posture: whether any device is present, MDM and control percentages | Yes | Yes | Yes |
| Endpoint posture: fleet counts and coverage | | Yes | Yes |
| Endpoint posture: per-device controls, primary user, last seen | | Yes | Yes |
| Endpoint posture: local administrator accounts per device | | | Yes |
| Organization name (`org_name`, the organization's display name) | | Yes | Yes |
| Organization ID (`org_id`, and the endpoint artifact's `organization_id`) | | Yes | Yes |

A trust run writes no organization, user, or device ID. The identity artifact's `org_domain` is then the domain most users' email addresses are at, or the administrators' when no user has one. From the audit level it is the organization ID.

### What it does not measure

- **Login activity / inactivity**: JumpCloud user records have no last sign-in time. JumpCloud records sign-ins as Directory Insights events, and the collector does not count them for inactivity. So `inactive_pct` is not emitted in the normalized artifact, and it has a `not_read` gap in the collector result.
- **Approved SaaS applications**: JumpCloud's SaaS Management API (`/api/v2/saas-management/applications`, scope `saas.readonly`) lists the applications an organization approved. The collector does not call it, so `authorized_third_party_apps_count` has a `not_read` gap.
- **Values JumpCloud does not report**: application provisioning, archived accounts, standing administrator access, password policy results, and password strength. Each has an `unsupported` gap.
- **Administrator MFA beyond TOTP**: JumpCloud's admin API reports TOTP enrollment and whether MFA is required, but not other factors such as security keys. The detailed artifact reports both separately, and the IDP artifact sets `privileged_mfa_coverage_pct` only when every privileged administrator who is not suspended has TOTP enrolled. Suspended administrators are left out of the admin counts. The IDP artifact's privileged counts also leave out the Read Only and Billing Only roles, which cannot change who has access or how users sign in.
- **Effective policy enforcement**: the detailed artifact describes policy *configuration* (which policies exist, what they require). It does not evaluate effective enforcement across targets, monitoring mode, or fallback behavior. The normalized artifact omits policy and device-access claims for this reason.
- **Complete event history**: audit event counts at the internal level summarize the fetched sample (capped at 5,000 rows). They are not necessarily complete seven-day totals.

### Incomplete discovery

Each paginated API surface has an internal safety cap (50,000 rows). When discovery is capped, the collector result has a partial gap with the code `too_large`. When a list ends before the total JumpCloud reported, the gap's code is `invalid_response`. In either case:

- V1 surfaces (users, apps, admins, systems) report `partial: true` in their metrics.
- V2 surfaces (groups, policies) emit a diagnostic warning.
- The identity artifact leaves out the sections that come from a partial list.

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

   `epack lock` resolves and pins the collector release in `epack.lock.yaml`. `epack collect` writes an `evidence-<timestamp>.epack` file containing `artifacts/jumpcloud.details.json`, `artifacts/jumpcloud.idp-posture.json`, and `artifacts/jumpcloud.endpoint-posture.json`. Inspect it with `epack inspect <file>`.

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

- **Service account (recommended):** in the Admin Portal, go to Settings > Service Accounts > + New, choose the Read Only role, and select API keys as the key type. The key is not tied to any one administrator. Service accounts cannot read `/api/organizations`, so from the audit level the detailed artifact omits `org_id` and `org_name`, each with a gap, and the identity artifact's `org_domain` comes from the organization the users belong to. Service accounts are not available to MSP organizations.
- **Personal API key:** click your account name in the bottom-left of the Admin Portal and choose My API Key. API access must first be enabled by an Administrator with Billing. Generating a new key revokes the previous one, and the key carries that administrator's full permissions.

### Required permissions

The API key needs read access to the calls below. JumpCloud's API reference lists a scope for each call but `/api/users`. A `permission_denied` gap names the call's scope as its `missing_permission`.

| Call | Scope |
|------|-------|
| System users (`/api/systemusers`) | `users.readonly` |
| Applications (`/api/applications`) | `applications.readonly` |
| Organizations (`/api/organizations`, optional) | `organizations.readonly` |
| Admin Portal administrators (`/api/users`) | none listed |
| Systems (`/api/systems`) | `systems.readonly` |
| User groups and system groups (`/api/v2/usergroups`, `/api/v2/systemgroups`) | `groups.readonly` |
| Authentication policies (`/api/v2/authn/policies`) | `authn.readonly` |
| Directory Insights events at internal level (`/insights/directory/v1/events` on `api.jumpcloud.com`) | `directoryinsights.readonly` |
| System Insights tables, requested only for OS families present in the fleet (`/api/v2/systeminsights/bitlocker_info`, `windows_security_center`, `windows_security_products`, `alf`, and `users` at internal level) | `systeminsights.readonly` |

JumpCloud's API reference does not document `/api/users`, so its call names no scope. System Insights must be enabled for the organization. A service account cannot read `/api/organizations`, as the note above says.

The run fails when the users cannot be read, or when `org_id` matches no listed organization. Any other surface that fails, including one that returns 401 or 403, is left out with a gap and a diagnostic. When a System Insights table is denied, the endpoint controls that need it are left out, with a `permission_denied` gap and availability entry.

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
make trace-map   # rewrite docs/schema/trace-map.json after a change to the code
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
