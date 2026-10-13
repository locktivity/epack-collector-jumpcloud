# epack-collector-jumpcloud

Collects JumpCloud identity, access, and device posture metrics for evidence packs.

## What it collects

Every run emits one detailed artifact:

- `artifacts/jumpcloud.json`: JumpCloud-specific posture

When user discovery is complete (not capped), a second normalized artifact is also emitted:

- `artifacts/jumpcloud.idp-posture.json`: normalized `evidencepack/idp-posture@v1` posture

The normalized artifact is omitted when user discovery is incomplete or there are no users, because percentages computed from a partial population would misrepresent actual coverage.

### Collection levels

Set the collection level in your pipeline configuration. This controls what data is gathered and how much detail is disclosed.

| Surface | Trust | Audit | Internal |
|---------|-------|-------|----------|
| User counts and MFA adoption percentages | Yes | Yes | Yes |
| Admin counts and admin MFA coverage | Yes | Yes | Yes |
| SSO app counts and coverage | Yes | Yes | Yes |
| Authentication policy configuration summary | Yes | Yes | Yes |
| Device/system counts, OS breakdown, MDM enrollment | Yes | Yes | Yes |
| Per-user inventory (username, email, state, MFA status) | | Yes | Yes |
| Per-app inventory (name, SSO type) | | Yes | Yes |
| User and system group inventory | | Yes | Yes |
| Per-device inventory (hostname, OS, agent, MDM) | | Yes | Yes |
| Per-policy inventory (name, type, MFA factors, conditions) | | Yes | Yes |
| Directory Insights audit events (7-day window) | | | Yes |

### What it does not measure

- **Login activity / inactivity**: the collector does not query per-user login timestamps, so `inactive_pct` is not emitted in the normalized artifact.
- **Effective policy enforcement**: the detailed artifact describes policy *configuration* (which policies exist, what they require). It does not evaluate effective enforcement across targets, monitoring mode, or fallback behavior. The normalized artifact omits policy and device-access claims for this reason.
- **Complete event history**: audit event counts at the internal level summarize the fetched sample (capped at 5,000 rows). They are not necessarily complete seven-day totals.

### Incomplete discovery

Each paginated API surface has an internal safety cap (50,000 rows). When discovery is capped:

- V1 surfaces (users, apps, admins, systems) report `partial: true` in their metrics and the server-reported total is preserved where available.
- V2 surfaces (groups, policies) emit a diagnostic warning when capped.
- The normalized artifact is omitted entirely when user discovery is partial.

## Quick start

```yaml
collectors:
  - name: jumpcloud
    config:
      org_id: ""  # optional, for MSP multi-tenant scenarios
    secrets:
      JUMPCLOUD_API_KEY: ${JUMPCLOUD_API_KEY}
```

## Configuration

| Key | Required | Description |
|-----|----------|-------------|
| `org_id` | No | JumpCloud organization ID (string). Required for MSP/multi-tenant setups where the API key has access to multiple organizations. Must be a string; a non-string value is rejected. |

When `org_id` is set, the collector validates it against the organization list. When unset and the API key returns multiple organizations, collection fails with a clear error.

## Authentication

Set `JUMPCLOUD_API_KEY` to a JumpCloud API key.

Generate one in the JumpCloud Admin Portal under your username > API Settings.

### Required permissions

The API key needs read access to:
- System users (`/api/systemusers`)
- Applications (`/api/applications`)
- Organizations (`/api/organizations`)
- Administrators (`/api/administrators`)
- Systems (`/api/systems`)
- User groups and system groups (`/api/v2/usergroups`, `/api/v2/systemgroups`)
- Authentication policies (`/api/v2/authn/policies`)
- Directory Insights events at internal level (`/insights/directory/v1/events` on `api.jumpcloud.com`)

Surfaces that return 403 degrade gracefully: that section is omitted and a diagnostic is recorded. A 401 from any surface is fatal.

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
