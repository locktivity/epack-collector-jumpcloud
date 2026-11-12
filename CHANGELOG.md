# Changelog

## Unreleased

## v0.2.3

- When JumpCloud leaves out a field a device's reading needs, the device counts as unknown, and the control's percentage is left out with a `partial` gap whose code is `invalid_response` and whose unmeasured count is those devices. The fields are a system's `lastContact`, `fde` object and `fde.active`, and a System Insights row's `system_id`, `collection_time`, and the columns its control is judged on. This covers the `hardening` and `protection` percentages in `artifacts/jumpcloud.endpoint-posture.json`, and each `passing_pct` under `device_controls` in `artifacts/jumpcloud.details.json`, which is null with the same gap. `metric_coverage` and the detailed device counts still count the device as unknown. The `fde` object is the agent's report, so it counts as left out only on a system with the agent. A system without the agent, such as a phone enrolled only in MDM, still has no disk encryption reading. A reading that JumpCloud's data leaves unknown, such as a stale reading or an unrecognized state, keeps the percentage over the devices that passed or failed, with no gap.
- An administrator JumpCloud lists with no `roleName` could hold any role. `admins.super_admin_count` in `artifacts/jumpcloud.details.json` is then null, and `artifacts/jumpcloud.idp-posture.json` leaves out `privileged_access.super_admin_count`, `privileged_users_count`, `privileged_mfa_user_count`, and `privileged_mfa_coverage_pct`. Each has a `partial` gap whose code is `invalid_response`. `privileged_users_present` is still written when another administrator holds a privileged role.

## v0.2.2

- The identity artifact's `privileged_access` counts administrators with every role but Read Only and Billing Only, which cannot change who has access or how users sign in. Command Runner, Help Desk, and Manager still count. The detailed artifact's `admins` section still counts every administrator who is not suspended.
- The identity artifact's `policy.mfa_required`, `mfa_required_user_count`, `mfa_required_coverage_pct` and `legacy_auth_blocked` are left out with a `not_read` gap. The collector reads JumpCloud's authentication policies for the detailed artifact, but does not work out what they enforce for every user and every sign-in.
- The collector is built on Go 1.26.11.

## v0.2.1

- The collector is built on epack v0.10.5.
- A trust run no longer writes the organization ID. `org_id` in `artifacts/jumpcloud.details.json` is written from the audit level. At trust, `org_domain` in `artifacts/jumpcloud.idp-posture.json` is the domain most users' email addresses are at, or the administrators' when no user has one. It used to be the organization ID. The audit and internal levels write what they did before.
- The collector result's `targets` says what the run was pointed at: the organization, chosen by `org_id` or, without it, found by the API key. It points at `artifacts/jumpcloud.details.json` as a whole, named by `org_id` and labeled by the new `org_name`, the organization's display name. `org_name` is written from the audit level, as `org_id` is, and left out with a gap when the organization list could not be read, as for a service account. A trust run leaves both out, so its target does not name the organization. A gap anywhere in the artifact that makes the run partial marks the organization incomplete.

## v0.2.0

- `scope.discovery_complete` in `artifacts/jumpcloud.endpoint-posture.json`, and `device_controls.discovery_complete` in `artifacts/jumpcloud.details.json`, are null when the systems list ends before the total JumpCloud reported or lists a device twice. Each then has an `invalid_response` gap. They used to be false. They are still false when the collector's row limit stops the list.
- Values JumpCloud reports in a call the collector does not make now have a `not_read` gap, which does not make the run partial. These are `user_security.inactive_pct` and `inactive_user_count`, from Directory Insights sign-in events. `app_security.authorized_third_party_apps_count` comes from SaaS Management. `hardening.screen_lock_compliant_pct` comes from the Apple MDM device API, and `compliance.compliant_pct` from the Google EMM device API. The first three had an `unsupported` gap.
- Disk encryption has a `not_read` gap when no device has a reading and the fleet has a Mac or a Linux device, since System Insights' `disk_encryption` table covers them. It had an `unsupported` gap.
- `compliance.compliant_pct` and the `patching` values now have gaps. The `patching` values have `unsupported` gaps, and their `availability` reason is `unsupported`. It used to be `not_configured`.
- A `not_read` value's `availability` reason is now `not_read`, and its message includes the API that reports it. `compliance.compliant_pct` used to give `not_configured`. `hardening.screen_lock_compliant_pct` used to give `unsupported`, and so did disk encryption with no reading on a fleet with a Mac or a Linux device.
- When System Insights has fresh readings for a control and none of them is a clear pass or fail, the control's `availability` reason is `source_error`. It used to be `unsupported`, with a message that no device had a source.
- The `unsupported` gaps on application provisioning and standing administrator access say that JumpCloud's documented APIs do not report them.
- Each operation in the collector result lists the scope JumpCloud's API reference gives for it as `permission`, such as `systeminsights.readonly`. A gap from a denied call has that scope as its `missing_permission`. The administrators list, `/api/users`, has none, since the reference does not document it.
