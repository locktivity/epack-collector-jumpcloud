package collector

// IDPPosture represents the normalized identity provider posture.
// This follows the evidencepack/idp-posture@v1 schema specification.
type IDPPosture struct {
	SchemaVersion    string                      `json:"schema_version"`
	CollectedAt      string                      `json:"collected_at"`
	Provider         string                      `json:"provider"`
	OrgDomain        string                      `json:"org_domain,omitempty"`
	UserSecurity     IDPPostureUserSecurity      `json:"user_security"`
	AppSecurity      *IDPPostureAppSecurity      `json:"app_security,omitempty"`
	PrivilegedAccess *IDPPosturePrivilegedAccess `json:"privileged_access,omitempty"`
	Lifecycle        *IDPPostureLifecycle        `json:"lifecycle,omitempty"`
}

// IDPPostureUserSecurity contains user security metrics.
type IDPPostureUserSecurity struct {
	MFACoveragePct          float64 `json:"mfa_coverage_pct"`
	MFAPhishingResistantPct float64 `json:"mfa_phishing_resistant_pct"`
	LockedOutPct            float64 `json:"locked_out_pct"`
}

// IDPPostureAppSecurity contains application security metrics.
type IDPPostureAppSecurity struct {
	SSOCoveragePct *float64 `json:"sso_coverage_pct,omitempty"`
}

// IDPPosturePrivilegedAccess contains privileged account posture metrics.
type IDPPosturePrivilegedAccess struct {
	PrivilegedUsersCount     int      `json:"privileged_users_count"`
	SuperAdminCount          int      `json:"super_admin_count"`
	PrivilegedMFACoveragePct *float64 `json:"privileged_mfa_coverage_pct,omitempty"`
}

// IDPPostureLifecycle contains account lifecycle posture metrics.
type IDPPostureLifecycle struct {
	SuspendedPct *float64 `json:"suspended_pct,omitempty"`
}

// ToIDPPosture transforms the JumpCloud-specific posture into the shared
// idp-posture@v1 shape.
//
// Returns nil when:
//   - there are no users (percentages would be zero/meaningless)
//   - user discovery was incomplete (percentages would misrepresent coverage)
//
// Sections that depend on optional surfaces (Apps, Admins) are only emitted
// when the corresponding data was successfully collected and is complete.
//
// Fields we deliberately omit:
//   - inactive_pct: the collector does not measure login activity
//   - policy/device_access: the collector observes policy configuration, not
//     effective enforcement. Policy data is in the detailed artifact.
func (o *OrgPosture) ToIDPPosture() *IDPPosture {
	if o.Users.Total == 0 {
		return nil
	}
	if o.Users.Partial {
		return nil
	}

	lockedOutPct := pct(o.Users.Locked, o.Users.Total)
	suspendedPct := pct(o.Users.Suspended, o.Users.Total)

	posture := &IDPPosture{
		SchemaVersion: SchemaVersion,
		CollectedAt:   o.CollectedAt,
		Provider:      "jumpcloud",
		UserSecurity: IDPPostureUserSecurity{
			MFACoveragePct:          o.Authentication.MFACoveragePct,
			MFAPhishingResistantPct: o.Authentication.WebAuthnEnrolledPct,
			LockedOutPct:            lockedOutPct,
		},
		Lifecycle: &IDPPostureLifecycle{
			SuspendedPct: &suspendedPct,
		},
	}

	if o.Apps != nil && o.Apps.TotalApps > 0 && !o.Apps.Partial {
		ssoPct := o.Apps.SSOCoveragePct
		posture.AppSecurity = &IDPPostureAppSecurity{
			SSOCoveragePct: &ssoPct,
		}
	}

	if o.Admins != nil && o.Admins.TotalAdmins > 0 && !o.Admins.Partial {
		posture.PrivilegedAccess = &IDPPosturePrivilegedAccess{
			PrivilegedUsersCount: o.Admins.TotalAdmins,
			SuperAdminCount:      o.Admins.SuperAdminCount,
		}
		// Only TOTP enrollment is observable. An admin without it may still
		// use another factor, so coverage is known only when every admin
		// has TOTP enrolled.
		if o.Admins.TOTPEnrolledCount == o.Admins.TotalAdmins {
			full := 100.0
			posture.PrivilegedAccess.PrivilegedMFACoveragePct = &full
		}
	}

	return posture
}
