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
	Policy           *IDPPosturePolicy           `json:"policy,omitempty"`
	Lifecycle        *IDPPostureLifecycle        `json:"lifecycle,omitempty"`
	DeviceAccess     *IDPPostureDeviceAccess     `json:"device_access,omitempty"`
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

// IDPPosturePolicy contains aggregated policy settings.
// Fields are only populated when policy data was successfully collected.
type IDPPosturePolicy struct {
	MFARequired                            bool  `json:"mfa_required"`
	PhishingResistantRequiredForPrivileged *bool `json:"phishing_resistant_required_for_privileged,omitempty"`
}

// IDPPostureLifecycle contains account lifecycle posture metrics.
type IDPPostureLifecycle struct {
	SuspendedPct *float64 `json:"suspended_pct,omitempty"`
}

// IDPPostureDeviceAccess contains managed-device posture.
type IDPPostureDeviceAccess struct {
	ManagedDeviceRequired *bool `json:"managed_device_required,omitempty"`
}

// ToIDPPosture transforms the JumpCloud-specific posture into the shared
// idp-posture@v1 shape.
//
// Returns nil when there are no users, because all percentages would be
// zero and indistinguishable from genuinely poor posture.
//
// Sections that depend on optional surfaces (Apps, Admins, Policies, Devices)
// are only emitted when the corresponding data was successfully collected.
// Unavailable sections are omitted rather than defaulted to zero, so
// consumers do not mistake missing data for a definite posture reading.
//
// Note: inactive_pct is not emitted because the collector does not yet
// measure user login activity timestamps.
func (o *OrgPosture) ToIDPPosture() *IDPPosture {
	if o.Users.Total == 0 {
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

	if o.Apps != nil && o.Apps.TotalApps > 0 {
		ssoPct := o.Apps.SSOCoveragePct
		posture.AppSecurity = &IDPPostureAppSecurity{
			SSOCoveragePct: &ssoPct,
		}
	}

	if o.Admins != nil && o.Admins.TotalAdmins > 0 {
		adminMFAPct := o.Admins.AdminMFACoveragePct
		posture.PrivilegedAccess = &IDPPosturePrivilegedAccess{
			PrivilegedUsersCount:     o.Admins.TotalAdmins,
			SuperAdminCount:          o.Admins.SuperAdminCount,
			PrivilegedMFACoveragePct: &adminMFAPct,
		}
	}

	// Only emit policy section when policies were successfully collected.
	// HasMFARequiredPolicy describes policy configuration, not effective
	// enforcement. A policy may target a subset of users.
	if o.Policies != nil {
		policy := &IDPPosturePolicy{
			MFARequired: o.Policies.HasMFARequiredPolicy,
		}
		if o.Policies.HasPhishingResistantAdminPolicy {
			v := true
			policy.PhishingResistantRequiredForPrivileged = &v
		}
		posture.Policy = policy
	}

	// Only emit device access when we have both policy and device data
	// confirming a managed-device condition exists.
	if o.Policies != nil && o.Policies.HasDeviceManagedCondition {
		v := true
		posture.DeviceAccess = &IDPPostureDeviceAccess{
			ManagedDeviceRequired: &v,
		}
	}

	return posture
}
