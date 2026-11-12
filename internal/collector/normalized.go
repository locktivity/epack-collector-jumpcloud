package collector

import "github.com/locktivity/epack/componentsdk"

// IDPPosture represents the normalized identity provider posture.
// This follows the evidencepack/idp-posture@v1 schema specification.
// A section whose source was not read in full is left out, with a gap. A
// percentage over an empty population is null. The counts behind the
// percentages are written from the audit level, as the schema marks them,
// and the present flags at every level.
//
// The policy and device_access sections are left out. The collector reads
// how policies are configured, which does not show what they enforce. The
// policy data is in the detailed artifact.
//
// privileged_access counts the administrators whose role can change who
// has access or how users sign in, which leaves out Read Only and Billing
// Only.
type IDPPosture struct {
	SchemaVersion    string                      `json:"schema_version"`
	CollectedAt      string                      `json:"collected_at"`
	Provider         string                      `json:"provider"`
	OrgDomain        string                      `json:"org_domain"`
	UserSecurity     *IDPPostureUserSecurity     `json:"user_security,omitempty"`
	AppSecurity      *IDPPostureAppSecurity      `json:"app_security,omitempty"`
	PrivilegedAccess *IDPPosturePrivilegedAccess `json:"privileged_access,omitempty"`
	Lifecycle        *IDPPostureLifecycle        `json:"lifecycle,omitempty"`
}

// IDPPostureUserSecurity covers the users who can sign in, the users
// neither suspended nor staged.
type IDPPostureUserSecurity struct {
	UsersPresent               *bool      `json:"users_present,omitempty"`
	UserCount                  *int       `json:"user_count,omitempty"`
	MFAUserCount               *int       `json:"mfa_user_count,omitempty"`
	PhishingResistantUserCount *int       `json:"phishing_resistant_user_count,omitempty"`
	LockedOutUserCount         *int       `json:"locked_out_user_count,omitempty"`
	MFACoveragePct             Percentage `json:"mfa_coverage_pct,omitzero"`
	MFAPhishingResistantPct    Percentage `json:"mfa_phishing_resistant_pct,omitzero"`
	LockedOutPct               Percentage `json:"locked_out_pct,omitzero"`
}

// IDPPostureAppSecurity contains application security metrics.
type IDPPostureAppSecurity struct {
	AppsPresent    *bool      `json:"apps_present,omitempty"`
	AppCount       *int       `json:"app_count,omitempty"`
	SSOAppCount    *int       `json:"sso_app_count,omitempty"`
	SSOCoveragePct Percentage `json:"sso_coverage_pct,omitzero"`
}

// IDPPosturePrivilegedAccess contains privileged account posture metrics.
type IDPPosturePrivilegedAccess struct {
	PrivilegedUsersPresent   *bool      `json:"privileged_users_present,omitempty"`
	PrivilegedUsersCount     *int       `json:"privileged_users_count,omitempty"`
	SuperAdminCount          *int       `json:"super_admin_count,omitempty"`
	PrivilegedMFAUserCount   *int       `json:"privileged_mfa_user_count,omitempty"`
	PrivilegedMFACoveragePct Percentage `json:"privileged_mfa_coverage_pct,omitzero"`
}

// IDPPostureLifecycle contains account lifecycle posture metrics over the
// users in every state.
type IDPPostureLifecycle struct {
	AccountsPresent       *bool      `json:"accounts_present,omitempty"`
	AccountCount          *int       `json:"account_count,omitempty"`
	SuspendedAccountCount *int       `json:"suspended_account_count,omitempty"`
	SuspendedPct          Percentage `json:"suspended_pct,omitzero"`
}

// ToIDPPosture transforms the JumpCloud-specific posture into the shared
// idp-posture@v1 shape. It returns nil when the organization could not be
// named, since the artifact requires org_domain.
//
// user_security and lifecycle come from the users, app_security from the
// applications, and privileged_access from the administrators. Each is left
// out when its list was not read in full.
// Each percentage is taken from its counts and rounded as the schema says.
// Where more is worse, as with locked-out users, it rounds up.
func (o *OrgPosture) ToIDPPosture() *IDPPosture {
	if o.orgDomain == "" {
		return nil
	}
	audit := componentsdk.Level(o.CollectedAtLevel).AtLeast(componentsdk.LevelAudit)
	atAudit := func(n int) *int {
		if audit {
			return &n
		}
		return nil
	}

	posture := &IDPPosture{
		SchemaVersion: SchemaVersion,
		CollectedAt:   o.CollectedAt,
		Provider:      "jumpcloud",
		OrgDomain:     o.orgDomain,
	}

	if pc := o.people; pc != nil && !o.Users.Partial {
		posture.UserSecurity = &IDPPostureUserSecurity{
			UsersPresent:               boolPtr(pc.active > 0),
			UserCount:                  atAudit(pc.active),
			MFAUserCount:               atAudit(pc.mfa),
			PhishingResistantUserCount: atAudit(pc.phishingResistant),
			LockedOutUserCount:         atAudit(pc.locked),
			MFACoveragePct:             known(componentsdk.Percent(pc.mfa, pc.active, componentsdk.RoundDown)),
			MFAPhishingResistantPct:    known(componentsdk.Percent(pc.phishingResistant, pc.active, componentsdk.RoundDown)),
			LockedOutPct:               known(componentsdk.Percent(pc.locked, pc.active, componentsdk.RoundUp)),
		}
		u := o.Users
		posture.Lifecycle = &IDPPostureLifecycle{
			AccountsPresent:       boolPtr(u.Total > 0),
			AccountCount:          atAudit(u.Total),
			SuspendedAccountCount: atAudit(u.Suspended),
			SuspendedPct:          known(componentsdk.Percent(u.Suspended, u.Total, componentsdk.RoundUp)),
		}
	}

	if a := o.Apps; a != nil && !a.Partial {
		posture.AppSecurity = &IDPPostureAppSecurity{
			AppsPresent:    boolPtr(a.TotalApps > 0),
			AppCount:       atAudit(a.TotalApps),
			SSOAppCount:    atAudit(a.SSOEnabledApps),
			SSOCoveragePct: known(componentsdk.Percent(a.SSOEnabledApps, a.TotalApps, componentsdk.RoundDown)),
		}
	}

	if a := o.Admins; a != nil && !a.Partial {
		// An administrator with no role could hold any role, so the values
		// that depend on roles are left out, with a gap. Another
		// administrator's privileged role still shows that one is present.
		pa := &IDPPosturePrivilegedAccess{}
		switch {
		case a.noRole == 0:
			pa.PrivilegedUsersPresent = boolPtr(a.privileged > 0)
			pa.PrivilegedUsersCount = atAudit(a.privileged)
			pa.SuperAdminCount = atAudit(*a.SuperAdminCount)
		case a.privileged > 0:
			pa.PrivilegedUsersPresent = boolPtr(true)
		}
		// Only TOTP enrollment is observable. An admin without it may still
		// use another factor, so coverage is known only when every
		// privileged admin has TOTP enrolled.
		if a.noRole == 0 && a.privilegedTOTP == a.privileged {
			pa.PrivilegedMFAUserCount = atAudit(a.privilegedTOTP)
			pa.PrivilegedMFACoveragePct = known(componentsdk.Percent(a.privilegedTOTP, a.privileged, componentsdk.RoundDown))
		}
		posture.PrivilegedAccess = pa
	}

	return posture
}

// idpPostureSources maps each normalized value to the detailed value it
// comes from, so a gap on the detailed value carries over. The counts are
// audit-level fields.
var idpPostureSources = []struct {
	normalized, detailed string
	audit                bool
}{
	{"/user_security/mfa_coverage_pct", "/authentication/mfa_coverage_pct", false},
	{"/user_security/mfa_phishing_resistant_pct", "/authentication/webauthn_enrolled_pct", false},
	{"/app_security/apps_present", "/apps/total_apps", false},
	{"/app_security/app_count", "/apps/total_apps", true},
	{"/app_security/sso_app_count", "/apps/sso_enabled_apps", true},
	{"/app_security/sso_coverage_pct", "/apps/sso_coverage_pct", false},
	{"/privileged_access/privileged_users_present", "/admins/total_admins", false},
	{"/privileged_access/privileged_users_count", "/admins/total_admins", true},
	{"/privileged_access/super_admin_count", "/admins/super_admin_count", true},
	{"/privileged_access/privileged_mfa_user_count", "/admins/totp_enrolled_count", true},
	{"/privileged_access/privileged_mfa_coverage_pct", "/admins/totp_enrolled_pct", false},
	{"/lifecycle/accounts_present", "/users/total", false},
	{"/lifecycle/account_count", "/users/total", true},
	{"/lifecycle/suspended_account_count", "/users/suspended", true},
	{"/lifecycle/suspended_pct", "/users/suspended", false},
}

// idpPostureUnread lists the normalized values the collector has no
// reading for, with the gap's code and reason. The code is unsupported for
// a value JumpCloud does not report and not_read for one it reports in a
// call the collector does not make. The counts are audit-level fields.
var idpPostureUnread = []struct {
	pointer string
	code    componentsdk.Code
	reason  string
	audit   bool
}{
	{"/app_security/authorized_third_party_apps_count", componentsdk.CodeNotRead, noThirdPartyApps, true},
	{"/app_security/deprovisioning_app_count", componentsdk.CodeUnsupported, noProvisioning, true},
	{"/app_security/deprovisioning_enabled_pct", componentsdk.CodeUnsupported, noProvisioning, false},
	{"/app_security/provisioning_app_count", componentsdk.CodeUnsupported, noProvisioning, true},
	{"/app_security/provisioning_enabled_pct", componentsdk.CodeUnsupported, noProvisioning, false},
	{"/lifecycle/archived_account_count", componentsdk.CodeUnsupported, noArchivedState, true},
	{"/lifecycle/archived_pct", componentsdk.CodeUnsupported, noArchivedState, false},
	{"/policy/legacy_auth_blocked", componentsdk.CodeNotRead, noPolicyEvaluation, false},
	{"/policy/mfa_required", componentsdk.CodeNotRead, noPolicyEvaluation, false},
	{"/policy/mfa_required_coverage_pct", componentsdk.CodeNotRead, noPolicyEvaluation, false},
	{"/policy/mfa_required_user_count", componentsdk.CodeNotRead, noPolicyEvaluation, true},
	{"/privileged_access/privileged_phishing_resistant_pct", componentsdk.CodeUnsupported, adminFactors, false},
	{"/privileged_access/privileged_phishing_resistant_user_count", componentsdk.CodeUnsupported, adminFactors, true},
	{"/privileged_access/standing_privileged_users_count", componentsdk.CodeUnsupported, noStandingAccess, true},
	{"/privileged_access/standing_privileged_users_present", componentsdk.CodeUnsupported, noStandingAccess, false},
	{"/user_security/inactive_pct", componentsdk.CodeNotRead, noSignInTime, false},
	{"/user_security/inactive_user_count", componentsdk.CodeNotRead, noSignInTime, true},
	{"/user_security/password_policy_noncompliant_pct", componentsdk.CodeUnsupported, noPasswordPolicyResult, false},
	{"/user_security/password_policy_noncompliant_user_count", componentsdk.CodeUnsupported, noPasswordPolicyResult, true},
	{"/user_security/weak_password_pct", componentsdk.CodeUnsupported, noPasswordStrength, false},
	{"/user_security/weak_password_user_count", componentsdk.CodeUnsupported, noPasswordStrength, true},
}

const (
	noThirdPartyApps       = "JumpCloud's SaaS Management API lists the applications the organization approved, which this collector does not read."
	noProvisioning         = "JumpCloud's documented application APIs do not say whether an application provisions or deprovisions users."
	noArchivedState        = "JumpCloud has no archived account state."
	adminFactors           = "JumpCloud reports only whether each administrator has TOTP enrolled."
	noStandingAccess       = "JumpCloud's administrator API does not say whether an administrator's access is standing or time-limited."
	noSignInTime           = "JumpCloud records sign-ins as Directory Insights events, which this collector does not count for inactivity."
	noPasswordPolicyResult = "JumpCloud does not report whether each user's password meets the password policy."
	noPasswordStrength     = "JumpCloud does not report how strong each user's password is."
	adminTOTPGap           = "JumpCloud reports only TOTP enrollment for administrators, and at least one administrator has no TOTP enrolled."
	noPolicyEvaluation     = "JumpCloud's authentication policies are in the detailed artifact, but this collector does not work out which users the enforced policies, together, require MFA of or block on every sign-in, or whether they block legacy authentication."
)

// recordIDPPostureGaps gives the idp-posture artifact the gaps of the
// detailed values it comes from, and an unsupported or not_read gap for
// each value the collector has no reading for. Below the audit level the
// artifact has no counts, so they get no gap.
func (o *OrgPosture) recordIDPPostureGaps(gaps *gapLog, usersShortfall error, unmeasured int) {
	audit := gaps.audit()
	if usersShortfall != nil {
		gaps.partial(unmeasured, usersShortfall, idp("/user_security"))
	}
	for _, s := range idpPostureSources {
		if s.audit && !audit {
			continue
		}
		gaps.mirror(s.detailed, idp(s.normalized))
	}
	if a := o.Admins; a != nil && !a.Partial && a.privilegedTOTP < a.privileged {
		gaps.unsupported(idp("/privileged_access/privileged_mfa_coverage_pct"), adminTOTPGap)
		if audit {
			gaps.unsupported(idp("/privileged_access/privileged_mfa_user_count"), adminTOTPGap)
		}
	}
	// The detailed super_admin_count's gap carries over through
	// idpPostureSources. A known privileged administrator still shows that
	// one is present, and a known one without TOTP already leaves the MFA
	// values out.
	if a := o.Admins; a != nil && !a.Partial && a.noRole > 0 {
		err := noRoleError(a)
		if a.privileged == 0 {
			gaps.partial(a.noRole, err, idp("/privileged_access/privileged_users_present"))
		}
		if a.privilegedTOTP == a.privileged {
			gaps.partial(a.noRole, err, idp("/privileged_access/privileged_mfa_coverage_pct"))
		}
		if audit {
			gaps.partial(a.noRole, err, idp("/privileged_access/privileged_users_count"))
			if a.privilegedTOTP == a.privileged {
				gaps.partial(a.noRole, err, idp("/privileged_access/privileged_mfa_user_count"))
			}
		}
	}
	for _, u := range idpPostureUnread {
		if u.audit && !audit {
			continue
		}
		gaps.unread(idp(u.pointer), u.code, u.reason)
	}
}

func boolPtr(v bool) *bool { return &v }
