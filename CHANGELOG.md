# Changelog

## Unreleased

## v0.2.0

- `scope.discovery_complete` in `artifacts/jumpcloud.endpoint-posture.json`, and `device_controls.discovery_complete` in `artifacts/jumpcloud.details.json`, are null when the systems list ends before the total JumpCloud reported or lists a device twice. Each then has an `invalid_response` gap. They used to be false. They are still false when the collector's row limit stops the list.
- Values JumpCloud reports in a call the collector does not make now have a `not_read` gap, which does not make the run partial. These are `user_security.inactive_pct` and `inactive_user_count`, from Directory Insights sign-in events. `app_security.authorized_third_party_apps_count` comes from SaaS Management. `hardening.screen_lock_compliant_pct` comes from the Apple MDM device API, and `compliance.compliant_pct` from the Google EMM device API. The first three had an `unsupported` gap.
- Disk encryption has a `not_read` gap when no device has a reading and the fleet has a Mac or a Linux device, since System Insights' `disk_encryption` table covers them. It had an `unsupported` gap.
- `compliance.compliant_pct` and the `patching` values now have gaps. The `patching` values have `unsupported` gaps, and their `availability` reason is `unsupported`. It used to be `not_configured`.
- A `not_read` value's `availability` reason is now `not_read`, and its message includes the API that reports it. `compliance.compliant_pct` used to give `not_configured`. `hardening.screen_lock_compliant_pct` used to give `unsupported`, and so did disk encryption with no reading on a fleet with a Mac or a Linux device.
- When System Insights has fresh readings for a control and none of them is a clear pass or fail, the control's `availability` reason is `source_error`. It used to be `unsupported`, with a message that no device had a source.
- The `unsupported` gaps on application provisioning and standing administrator access say that JumpCloud's documented APIs do not report them.
- Each operation in the collector result lists the scope JumpCloud's API reference gives for it as `permission`, such as `systeminsights.readonly`. A gap from a denied call has that scope as its `missing_permission`. The administrators list, `/api/users`, has none, since the reference does not document it.
