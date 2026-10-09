# epack-collector-jumpcloud

Collects JumpCloud identity, access, and device posture metrics for evidence packs.

## What it collects

Two artifacts are emitted on every run:

1. `artifacts/jumpcloud.json`: detailed JumpCloud-specific posture
2. `artifacts/jumpcloud.idp-posture.json`: normalized `evidencepack/idp-posture@v1` posture

### Collection levels

| Surface | Trust | Audit | Internal |
|---------|-------|-------|----------|
| User counts and MFA adoption percentages | Yes | Yes | Yes |
| Admin counts and admin MFA coverage | Yes | Yes | Yes |
| SSO app counts and coverage | Yes | Yes | Yes |
| Authentication policy summary (MFA required, device trust) | Yes | Yes | Yes |
| Device/system counts, OS breakdown, MDM enrollment | Yes | Yes | Yes |
| Per-user inventory (username, email, state, MFA status) | | Yes | Yes |
| Per-app inventory (name, SSO type, active) | | Yes | Yes |
| User and system group inventory | | Yes | Yes |
| Per-device inventory (hostname, OS, agent, MDM) | | Yes | Yes |
| Per-policy inventory (name, type, MFA factors, device trust) | | Yes | Yes |
| 7-day Directory Insights audit events | | | Yes |

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
| `org_id` | No | JumpCloud organization ID. Required only for MSP/multi-tenant setups. |

## Authentication

Set `JUMPCLOUD_API_KEY` to a JumpCloud API key (prefixed `jca_`).

Generate one in the JumpCloud Admin Portal under your username > API Settings.

### Required permissions

The API key needs read access to:
- System users
- Applications
- Administrators
- Systems
- User groups / System groups
- Authentication policies
- Directory Insights events (internal level only)

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
