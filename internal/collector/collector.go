package collector

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-jumpcloud/internal/jumpcloud"
	"github.com/locktivity/epack/componentsdk"
)

const auditWindowDays = 7

// Collect gathers JumpCloud posture data at the requested level. It fails
// only when the users cannot be listed or the configured organization does
// not resolve. A value it cannot read after that is left out with a gap,
// which the run's recorder holds.
func (c *Collector) Collect(ctx context.Context, level componentsdk.Level) (*OrgPosture, error) {
	diag := &diagnosticsTracker{}
	gaps := newGapLog(c.cfg.Recorder, level)
	now := c.now().UTC()
	audit := level.AtLeast(componentsdk.LevelAudit)
	details := c.selected(detailedPath)

	stepCtx, step := componentsdk.StartStep(ctx, "users", "Fetching users")
	users, serverUserTotal, err := c.client.ListSystemUsers(stepCtx)
	step.End()
	if err != nil {
		return nil, fmt.Errorf("listing users: %w", err)
	}
	userShortfall := listShortfall(jumpcloud.OpListSystemUsers, len(users), serverUserTotal)

	posture := &OrgPosture{
		SchemaVersion:    SchemaVersion,
		CollectedAt:      now.Format(time.RFC3339),
		CollectedAtLevel: string(level),
		Users:            computeUserMetrics(users, userShortfall != nil),
		Authentication:   computeAuthMetrics(users),
		people:           countPeople(users),
	}
	if userShortfall != nil {
		gaps.partial(serverUserTotal-len(users), userShortfall, detailed("/users"), detailed("/authentication"))
	}

	stepCtx, step = componentsdk.StartStep(ctx, "organization", "Fetching the organization")
	org, orgErr := c.client.GetOrganization(stepCtx, c.cfg.OrgID)
	step.End()
	var orgID, orgName string
	switch {
	case orgErr != nil && isOrgValidationError(orgErr):
		return nil, orgErr
	case orgErr != nil:
		diag.surfaceWarning("organization", safeDiagError(orgErr))
		if audit {
			gaps.notCollected(orgErr, detailed("/org_id"), detailed("/org_name"))
		}
	case org == nil:
		if audit {
			gaps.invalid(detailed("/org_id"), "JumpCloud listed no organization for the API key.")
			gaps.invalid(detailed("/org_name"), "JumpCloud listed no organization for the API key.")
		}
	default:
		orgID, orgName = org.ID, org.DisplayName
	}
	gaps.rec.SignedInAs(componentsdk.Principal{
		Provider:   "jumpcloud",
		Kind:       "api_key",
		TenantID:   orgID,
		AuthMethod: componentsdk.AuthAPIToken,
	})
	chosen, key := componentsdk.ChosenByDiscovery, ""
	if c.cfg.OrgID != "" {
		chosen, key = componentsdk.ChosenByConfig, "org_id"
	}
	gaps.rec.Targets(componentsdk.TargetOrganization, detailed(""), "/org_id").ChosenBy(chosen, key).Label("/org_name")
	if audit {
		posture.OrgID = orgID
		posture.OrgName = orgName
		posture.orgDomain = orgID
		if posture.orgDomain == "" {
			posture.orgDomain = userOrganization(users)
		}
	}

	stepCtx, step = componentsdk.StartStep(ctx, "applications", "Fetching applications")
	apps, serverAppTotal, appErr := c.client.ListApplications(stepCtx)
	step.End()
	var appShortfall error
	if appErr != nil {
		recordSurfaceError(diag, "applications", appErr)
		gaps.notCollected(appErr, detailed("/apps"))
	} else {
		appShortfall = listShortfall(jumpcloud.OpListApplications, len(apps), serverAppTotal)
		posture.Apps = computeAppMetrics(apps, appShortfall != nil)
		if appShortfall != nil {
			gaps.partial(serverAppTotal-len(apps), appShortfall, detailed("/apps"))
		}
	}

	stepCtx, step = componentsdk.StartStep(ctx, "administrators", "Fetching administrators")
	admins, serverAdminTotal, adminErr := c.client.ListAdministrators(stepCtx)
	step.End()
	if !audit {
		posture.orgDomain = orgEmailDomain(users, admins)
	}
	if adminErr != nil {
		recordSurfaceError(diag, "administrators", adminErr)
		gaps.notCollected(adminErr, detailed("/admins"))
	} else {
		adminShortfall := listShortfall(jumpcloud.OpListAdministrators, len(admins), serverAdminTotal)
		posture.Admins = computeAdminMetrics(admins, adminShortfall != nil)
		if adminShortfall != nil {
			gaps.partial(serverAdminTotal-len(admins), adminShortfall, detailed("/admins"))
		}
		if posture.Admins.noRole > 0 {
			gaps.partial(posture.Admins.noRole, noRoleError(posture.Admins), detailed("/admins/super_admin_count"))
		}
	}

	var policies []jumpcloud.AuthPolicy
	var policyErr error
	var policyCapped bool
	if details {
		stepCtx, step = componentsdk.StartStep(ctx, "policies", "Fetching authentication policies")
		policies, policyCapped, policyErr = c.client.ListAuthPolicies(stepCtx)
		step.End()
		if policyErr != nil {
			recordSurfaceError(diag, "auth_policies", policyErr)
			gaps.notCollected(policyErr, detailed("/policies"))
		} else {
			posture.Policies = computePolicyMetrics(policies)
			if policyCapped {
				diag.surfaceWarning("auth_policies", "results capped at internal limit; policy inventory may be incomplete")
				gaps.partial(0, capped(jumpcloud.OpListAuthPolicies, jumpcloud.MaxResults), detailed("/policies"))
			}
		}
	}

	stepCtx, step = componentsdk.StartStep(ctx, "devices", "Fetching systems")
	systems, serverSysTotal, sysErr := c.client.ListSystems(stepCtx)
	var endpointIn *endpointInputs
	var sysShortfall error
	var sysUnmeasured int
	if sysErr != nil {
		recordSurfaceError(diag, "systems", sysErr)
		gaps.notCollected(sysErr, detailed("/devices"), detailed("/device_controls"), endpoint(""))
	} else {
		distinct, _ := reconcileSystems(systems, now)
		sysShortfall = systemsShortfall(len(systems), len(distinct), serverSysTotal)
		sysUnmeasured = serverSysTotal - len(distinct)
		posture.Devices = computeDeviceMetrics(distinct, sysShortfall != nil)
		if sysShortfall != nil {
			gaps.partial(sysUnmeasured, sysShortfall, detailed("/devices"))
		}
		endpointIn = &endpointInputs{
			systems:     systems,
			serverTotal: serverSysTotal,
			level:       level,
			now:         now,
			maxAge:      c.cfg.maxObservationAge(),
		}
		c.fetchEndpointTelemetry(stepCtx, diag, endpointIn)
	}
	step.End()

	if audit {
		c.status("Building inventories")
		posture.UserInventory = buildUserInventory(users)
		gaps.inventory(posture.UserInventory.Truncated, posture.UserInventory.TruncatedDropped, MaxUsers, userShortfall,
			serverUserTotal-len(users), "/user_inventory/per_user")
		switch {
		case appErr != nil:
			gaps.notCollected(appErr, detailed("/app_inventory"))
		default:
			posture.AppInventory = buildAppInventory(apps)
			gaps.inventory(false, 0, 0, appShortfall, serverAppTotal-len(apps), "/app_inventory/per_app")
		}
		if sysErr != nil {
			gaps.notCollected(sysErr, detailed("/device_inventory"))
		} else {
			posture.DeviceInventory = buildDeviceInventory(systems)
			gaps.inventory(posture.DeviceInventory.Truncated, posture.DeviceInventory.TruncatedDropped, MaxDevices, sysShortfall,
				sysUnmeasured, "/device_inventory/per_device")
		}
		if details {
			if policyErr != nil {
				gaps.notCollected(policyErr, detailed("/policy_inventory"))
			} else {
				posture.PolicyInventory = buildPolicyInventory(policies)
				if policyCapped {
					gaps.partial(0, capped(jumpcloud.OpListAuthPolicies, jumpcloud.MaxResults), detailed("/policy_inventory/auth_policies"))
				}
			}
			c.collectGroups(ctx, diag, gaps, posture)
		}
	}

	if level.AtLeast(componentsdk.LevelInternal) && details {
		c.collectAuditLog(ctx, diag, gaps, posture, now)
	}

	if endpointIn != nil {
		endpointIn.users = users
		endpointIn.orgID = posture.OrgID
		ep := buildEndpointPosture(*endpointIn)
		posture.endpoint = ep
		posture.DeviceControls = deviceControlsFrom(ep)
		if posture.DeviceInventory != nil {
			for i := range posture.DeviceInventory.PerDevice {
				row := &posture.DeviceInventory.PerDevice[i]
				row.Controls = ep.controlsByDevice[row.DeviceID]
			}
		}
		recordEndpointGaps(gaps, ep, posture, endpointIn, sysShortfall)
	}

	switch {
	case posture.orgDomain != "":
		posture.recordIDPPostureGaps(gaps, userShortfall, serverUserTotal-len(users))
	case !audit:
		gaps.invalid(idp(""), "No user or administrator has an email address whose domain names the organization.")
	case orgErr != nil:
		gaps.notCollected(orgErr, idp(""))
	default:
		gaps.invalid(idp(""), "JumpCloud listed no organization for the API key, and no user names one.")
	}

	posture.Diagnostics = diag.toDiagnostics()
	return posture, nil
}

// collectGroups reads the user and system groups for the audit level. A
// list that fails is null with a gap, and the other list is still written.
func (c *Collector) collectGroups(ctx context.Context, diag *diagnosticsTracker, gaps *gapLog, posture *OrgPosture) {
	stepCtx, step := componentsdk.StartStep(ctx, "groups", "Fetching user and system groups")
	defer step.End()
	userGroups, ugCapped, ugErr := c.client.ListUserGroups(stepCtx)
	if ugErr != nil {
		recordSurfaceError(diag, "user_groups", ugErr)
		gaps.notCollected(ugErr, detailed("/group_inventory/user_groups"))
	} else if ugCapped {
		diag.surfaceWarning("user_groups", "results capped at internal limit; group inventory may be incomplete")
		gaps.partial(0, capped(jumpcloud.OpListUserGroups, jumpcloud.MaxResults), detailed("/group_inventory/user_groups"))
	}
	systemGroups, sgCapped, sgErr := c.client.ListSystemGroups(stepCtx)
	if sgErr != nil {
		recordSurfaceError(diag, "system_groups", sgErr)
		gaps.notCollected(sgErr, detailed("/group_inventory/system_groups"))
	} else if sgCapped {
		diag.surfaceWarning("system_groups", "results capped at internal limit; group inventory may be incomplete")
		gaps.partial(0, capped(jumpcloud.OpListSystemGroups, jumpcloud.MaxResults), detailed("/group_inventory/system_groups"))
	}
	if ugErr == nil || sgErr == nil {
		posture.GroupInventory = buildGroupInventory(userGroups, ugErr == nil, systemGroups, sgErr == nil)
	}
}

// collectAuditLog reads the last auditWindowDays of Directory Insights
// events for the internal level.
func (c *Collector) collectAuditLog(ctx context.Context, diag *diagnosticsTracker, gaps *gapLog, posture *OrgPosture, now time.Time) {
	stepCtx, step := componentsdk.StartStep(ctx, "audit_log", "Fetching audit events")
	defer step.End()
	start := now.Add(-auditWindowDays * 24 * time.Hour)
	events, err := c.client.QueryEvents(stepCtx, "directory", start, now, MaxAuditEvents+1)
	if err != nil {
		recordSurfaceError(diag, "audit_log", err)
		gaps.notCollected(err, detailed("/audit_log"))
		return
	}
	posture.AuditLog = buildAuditLog(events)
	if posture.AuditLog.Truncated {
		cut := truncated("audit_log.events", MaxAuditEvents, posture.AuditLog.TruncatedDropped)
		gaps.partial(posture.AuditLog.TruncatedDropped, cut, detailed("/audit_log/events"), detailed("/audit_log/count_by_type"))
	}
}

// recordEndpointGaps records the gaps of the endpoint artifact and of the
// detailed device controls, then mirrors the detailed gaps onto the
// endpoint values copied from them. sysShortfall is set whenever discovery
// is incomplete, since both compare the distinct device IDs with the total.
func recordEndpointGaps(gaps *gapLog, ep *EndpointPosture, posture *OrgPosture, in *endpointInputs, sysShortfall error) {
	audit := gaps.audit()

	if !ep.discovered() {
		unmeasured := in.serverTotal - len(ep.controlsByDevice)
		for _, m := range measuredMetrics {
			gaps.partial(unmeasured, sysShortfall, detailed(m.summary))
		}
		gaps.partial(unmeasured, sysShortfall, endpoint("/fleet"))
		if ep.Scope.DiscoveryComplete == nil {
			gaps.notCollected(sysShortfall, detailed("/device_controls/discovery_complete"))
		}
	}

	for _, m := range measuredMetrics {
		if u := ep.unread[m.control]; len(u.devices) > 0 {
			gaps.partial(len(u.devices), u.first, detailed(m.summary))
		} else if u := ep.missing[m.control]; len(u.devices) > 0 && ep.discovered() {
			gaps.partial(len(u.devices), u.first, detailed(m.summary+"/passing_pct"))
		}
	}

	if audit {
		for i, row := range ep.Devices {
			for _, m := range measuredMetrics {
				if err := ep.unread[m.control].devices[row.DeviceID]; err != nil {
					gaps.notCollected(err, endpoint(rowPointer("/devices", i, "controls")+"/"+m.control))
				}
			}
		}
		if posture.DeviceInventory != nil {
			for i, row := range posture.DeviceInventory.PerDevice {
				for _, m := range measuredMetrics {
					if err := ep.unread[m.control].devices[row.DeviceID]; err != nil {
						gaps.notCollected(err, detailed(rowPointer("/device_inventory/per_device", i, "controls")+"/"+m.control))
					}
				}
			}
		}
		if fail := in.insightUsers.failure(); fail != nil {
			for i := range ep.Devices {
				gaps.notCollected(fail, endpoint(rowPointer("/devices", i, "local_admin_accounts")))
			}
		}
		if ep.truncatedDevices > 0 {
			gaps.partial(ep.truncatedDevices, truncated("devices", MaxDevices, ep.truncatedDevices), endpoint("/devices"))
		}
	}

	for _, u := range unmeasuredEndpointValues {
		if u.path == "" && !audit {
			continue
		}
		gaps.unread(endpoint(u.pointer), u.code, u.reason)
	}
	for _, m := range measuredMetrics {
		if code, ok := ep.noSource[m.path]; ok {
			gaps.unread(endpoint(m.pointer), code, noSourceReason(code))
		}
	}

	if audit {
		gaps.mirror("/org_id", endpoint("/organization_id"))
	}
	gaps.mirror("/device_controls/discovery_complete", endpoint("/scope/discovery_complete"))
	gaps.mirror("/device_controls/max_observation_age_seconds", endpoint("/scope/max_observation_age_seconds"))
	for _, m := range measuredMetrics {
		gaps.mirror(m.summary+"/passing_pct", endpoint(m.pointer))
		if !audit {
			continue
		}
		for _, count := range coverageCounts {
			gaps.mirror(m.summary+"/"+count.detailed, endpoint("/metric_coverage/"+m.path+"/"+count.normalized))
		}
	}
}

// coverageCounts names each coverage count in the detailed artifact and in
// the endpoint artifact.
var coverageCounts = []struct{ detailed, normalized string }{
	{"passing_devices_count", "passing_device_count"},
	{"failing_devices_count", "failing_device_count"},
	{"unknown_devices_count", "unknown_device_count"},
	{"not_applicable_devices_count", "not_applicable_device_count"},
}

func recordSurfaceError(diag *diagnosticsTracker, surface string, err error) {
	if isDenied(err) {
		diag.surfacePermissionDenied(surface, safeDiagError(err))
	} else {
		diag.surfaceWarning(surface, safeDiagError(err))
	}
}

func computeUserMetrics(users []jumpcloud.SystemUser, partial bool) UserMetrics {
	m := UserMetrics{Total: len(users), Partial: partial}
	for _, u := range users {
		switch u.State {
		case "ACTIVATED":
			m.Active++
		case "STAGED":
			m.Staged++
		case "SUSPENDED":
			m.Suspended++
		}
		if u.AccountLocked {
			m.Locked++
		}
	}
	return m
}

// countPeople counts the users who can sign in, and those of them with MFA,
// with phishing-resistant MFA, and locked out.
func countPeople(users []jumpcloud.SystemUser) *peopleCounts {
	pc := &peopleCounts{}
	for _, u := range users {
		if !canSignIn(u) {
			continue
		}
		pc.active++
		if hasMFA(u) {
			pc.mfa++
		}
		if u.MFAEnrollment.HasPhishingResistantMFA() {
			pc.phishingResistant++
		}
		if u.AccountLocked {
			pc.locked++
		}
	}
	return pc
}

// canSignIn reports whether the user is neither suspended nor staged.
func canSignIn(u jumpcloud.SystemUser) bool {
	return u.State != "SUSPENDED" && u.State != "STAGED"
}

// hasMFA reports whether the user has any MFA method enrolled. Without an
// enrollment record, the TOTP flag decides.
func hasMFA(u jumpcloud.SystemUser) bool {
	if u.MFAEnrollment != nil {
		return u.MFAEnrollment.HasAnyMFA()
	}
	return u.TOTPEnabled
}

// orgEmailDomain names the organization by the domain most of the users'
// email addresses are at, or, in an organization with no user email, the
// administrators'. It returns "" when no one has an email address.
func orgEmailDomain(users []jumpcloud.SystemUser, admins []jumpcloud.Administrator) string {
	emails := make([]string, 0, len(users))
	for _, u := range users {
		emails = append(emails, u.Email)
	}
	if domain := emailDomain(emails); domain != "" {
		return domain
	}
	emails = emails[:0]
	for _, a := range admins {
		emails = append(emails, a.Email)
	}
	return emailDomain(emails)
}

// emailDomain returns the domain most of the email addresses are at, the
// first by name on a tie, or "" when none has one.
func emailDomain(emails []string) string {
	counts := map[string]int{}
	for _, email := range emails {
		if at := strings.LastIndex(email, "@"); at >= 0 && at < len(email)-1 {
			counts[strings.ToLower(email[at+1:])]++
		}
	}
	best := ""
	for domain, n := range counts {
		if n > counts[best] || n == counts[best] && domain < best {
			best = domain
		}
	}
	return best
}

// userOrganization returns the organization the users name, or "" when none
// does or they disagree.
func userOrganization(users []jumpcloud.SystemUser) string {
	org := ""
	for _, u := range users {
		switch {
		case u.Organization == "":
		case org == "":
			org = u.Organization
		case org != u.Organization:
			return ""
		}
	}
	return org
}

func computeAuthMetrics(users []jumpcloud.SystemUser) AuthenticationMetrics {
	if len(users) == 0 {
		return AuthenticationMetrics{}
	}

	var mfaCount, totpCount, webauthnCount, pushCount, notEnrolledCount, portalMFACount int
	for _, u := range users {
		if !canSignIn(u) {
			continue
		}

		if u.MFAEnrollment != nil {
			if u.MFAEnrollment.TOTPStatus == "ENROLLED" {
				totpCount++
			}
			if u.MFAEnrollment.WebAuthnStatus == "ENROLLED" {
				webauthnCount++
			}
			if u.MFAEnrollment.PushStatus == "ENROLLED" {
				pushCount++
			}
		} else if u.TOTPEnabled {
			totpCount++
		}

		if hasMFA(u) {
			mfaCount++
		} else {
			notEnrolledCount++
		}

		if u.EnableUserPortalMultifactor {
			portalMFACount++
		}
	}

	activeCount := activeUserCount(users)
	return AuthenticationMetrics{
		MFACoveragePct:         pct(mfaCount, activeCount),
		TOTPEnrolledPct:        pct(totpCount, activeCount),
		WebAuthnEnrolledPct:    pct(webauthnCount, activeCount),
		PushEnrolledPct:        pct(pushCount, activeCount),
		MFANotEnrolledCount:    notEnrolledCount,
		PortalMFARequiredCount: portalMFACount,
	}
}

// computeAdminMetrics counts the administrators who are not suspended. A
// suspended administrator has no Admin Portal or API access. An
// administrator with no roleName could hold any role, so the super admin
// count is left out.
func computeAdminMetrics(admins []jumpcloud.Administrator, partial bool) *AdminMetrics {
	m := &AdminMetrics{Partial: partial}
	superAdmins := 0
	for _, a := range admins {
		if a.Suspended {
			continue
		}
		m.TotalAdmins++
		if a.TOTPEnrolled {
			m.TOTPEnrolledCount++
		}
		if a.EnableMultiFactor {
			m.MFARequiredCount++
		}
		if a.RoleName == "" {
			m.noRole++
			continue
		}
		if isSuperAdmin(a.RoleName) {
			superAdmins++
		}
		if isPrivileged(a.RoleName) {
			m.privileged++
			if a.TOTPEnrolled {
				m.privilegedTOTP++
			}
		}
	}
	if m.noRole == 0 {
		m.SuperAdminCount = &superAdmins
	}
	m.TOTPEnrolledPct = pct(m.TOTPEnrolledCount, m.TotalAdmins)
	return m
}

// noRoleError is the error for the administrators JumpCloud listed with
// no roleName.
func noRoleError(m *AdminMetrics) error {
	return componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf(
		"%s: no roleName for %d of the %d administrators who are not suspended",
		jumpcloud.OpListAdministrators, m.noRole, m.TotalAdmins))
}

// isPrivileged reports whether an administrator with roleName can change
// who has access, reset a user's credentials, or change sign-in settings.
// Read Only can only read, and Billing Only can only manage billing. Every
// other role can do one of these, Command Runner included, since its
// commands run on the organization's devices.
func isPrivileged(roleName string) bool {
	return !strings.EqualFold(roleName, "Read Only") && !strings.EqualFold(roleName, "Billing Only")
}

// isSuperAdmin returns true only for the highest-privilege JumpCloud role.
// "Administrator With Billing" has unrestricted access including billing,
// administrator management, and MTP control. The plain "Administrator" role
// lacks some of these permissions and is counted as privileged but not as
// the highest-privilege/super-admin tier.
func isSuperAdmin(roleName string) bool {
	return roleName == "Administrator With Billing"
}

func computeAppMetrics(apps []jumpcloud.Application, partial bool) *AppMetrics {
	if len(apps) == 0 {
		return &AppMetrics{Partial: partial}
	}
	ssoCount := 0
	for _, a := range apps {
		if a.IsSSOEnabled() {
			ssoCount++
		}
	}
	return &AppMetrics{
		TotalApps:      len(apps),
		SSOEnabledApps: ssoCount,
		SSOCoveragePct: pct(ssoCount, len(apps)),
		Partial:        partial,
	}
}

// computePolicyMetrics summarizes policy configuration. These metrics describe
// what policies exist, not what is effectively enforced. A policy that requires
// MFA for a subset of users is counted as "has MFA-required policy" but does
// not imply org-wide MFA enforcement. The normalized artifact does not carry
// these as enforcement claims.
func computePolicyMetrics(policies []jumpcloud.AuthPolicy) *PolicyMetrics {
	m := &PolicyMetrics{TotalPolicies: len(policies)}
	for _, p := range policies {
		if p.Disabled {
			continue
		}
		if p.Effect != nil && p.Effect.Obligations != nil {
			if p.Effect.Obligations.MFA != nil && p.Effect.Obligations.MFA.Required {
				m.MFARequiredPolicies++
				m.HasMFARequiredPolicy = true

				if p.Type == "admin_portal" && isPhishingResistantOnly(p.Effect.Obligations.MFAFactors) {
					m.HasPhishingResistantAdminPolicy = true
				}
			}
		}
		if p.ConditionHasDeviceManaged() {
			m.HasDeviceManagedCondition = true
		}
	}
	return m
}

// isPhishingResistantOnly returns true when the factor list ONLY allows
// phishing-resistant methods (WEBAUTHN/FIDO2), meaning weaker methods are
// excluded. An empty list means any factor is accepted.
func isPhishingResistantOnly(factors []jumpcloud.MFAFactorEntry) bool {
	if len(factors) == 0 {
		return false
	}
	for _, f := range factors {
		switch f.Type {
		case "WEBAUTHN", "FIDO2":
			// phishing-resistant, OK
		default:
			return false
		}
	}
	return true
}

// computeDeviceMetrics counts the systems reconcileSystems returns, one per
// device ID.
func computeDeviceMetrics(systems []*jumpcloud.System, partial bool) *DeviceMetrics {
	m := &DeviceMetrics{
		TotalSystems: len(systems),
		OSBreakdown:  make(map[string]int),
		Partial:      partial,
	}
	for _, s := range systems {
		if s.Active {
			m.ActiveSystems++
		}
		if s.HasMDM() {
			m.MDMEnrolled++
		}
		os := normalizeOS(s.OS)
		if os != "" {
			m.OSBreakdown[os]++
		}
	}
	return m
}

func buildUserInventory(users []jumpcloud.SystemUser) *UserInventory {
	rows := make([]UserRow, 0, len(users))
	for _, u := range users {
		row := UserRow{
			Username:      u.Username,
			Email:         u.Email,
			State:         u.State,
			TOTPEnabled:   u.TOTPEnabled,
			AccountLocked: u.AccountLocked,
			Created:       u.Created,
		}
		if u.MFAEnrollment != nil {
			row.MFAEnrolled = u.MFAEnrollment.HasAnyMFA()
			row.WebAuthnEnabled = u.MFAEnrollment.WebAuthnStatus == "ENROLLED"
			if u.MFAEnrollment.TOTPStatus == "ENROLLED" {
				row.TOTPEnabled = true
			}
		} else {
			row.MFAEnrolled = u.TOTPEnabled
		}
		rows = append(rows, row)
	}
	kept, truncated, dropped := truncateUsers(rows)
	return &UserInventory{
		PerUser:          kept,
		Truncated:        truncated,
		TruncatedDropped: dropped,
	}
}

func buildAppInventory(apps []jumpcloud.Application) *AppInventory {
	rows := make([]AppRow, 0, len(apps))
	for _, a := range apps {
		row := AppRow{Name: appDisplayName(a), SSOEnabled: a.IsSSOEnabled()}
		if a.SSO != nil {
			row.SSOType = a.SSO.Type
		}
		rows = append(rows, row)
	}
	return &AppInventory{PerApp: rows}
}

// buildGroupInventory lists the groups of each kind that was read. A kind
// that was not read stays null.
func buildGroupInventory(userGroups []jumpcloud.UserGroup, usersRead bool, systemGroups []jumpcloud.SystemGroup, systemsRead bool) *GroupInventory {
	inv := &GroupInventory{}
	if usersRead {
		inv.UserGroups = make([]GroupRow, 0, len(userGroups))
		for _, g := range userGroups {
			inv.UserGroups = append(inv.UserGroups, GroupRow{Name: g.Name, Type: g.Type})
		}
	}
	if systemsRead {
		inv.SystemGroups = make([]GroupRow, 0, len(systemGroups))
		for _, g := range systemGroups {
			inv.SystemGroups = append(inv.SystemGroups, GroupRow{Name: g.Name, Type: g.Type})
		}
	}
	return inv
}

func buildDeviceInventory(systems []jumpcloud.System) *DeviceInventory {
	rows := make([]DeviceRow, 0, len(systems))
	for _, s := range systems {
		rows = append(rows, DeviceRow{
			DeviceID:     s.ID,
			Hostname:     s.Hostname,
			OS:           s.OS,
			OSVersion:    s.OSVersionString(),
			Active:       s.Active,
			AgentVersion: s.AgentVersion,
			MDMEnrolled:  s.HasMDM(),
		})
	}
	kept, truncated, dropped := truncateDevices(rows)
	return &DeviceInventory{
		PerDevice:        kept,
		Truncated:        truncated,
		TruncatedDropped: dropped,
	}
}

func buildPolicyInventory(policies []jumpcloud.AuthPolicy) *PolicyInventory {
	rows := make([]AuthPolicyRow, 0, len(policies))
	for _, p := range policies {
		row := AuthPolicyRow{
			Name:          p.Name,
			Type:          p.Type,
			Disabled:      p.Disabled,
			DeviceManaged: p.ConditionHasDeviceManaged(),
		}
		if p.Effect != nil && p.Effect.Obligations != nil {
			if p.Effect.Obligations.MFA != nil {
				row.MFARequired = p.Effect.Obligations.MFA.Required
			}
			for _, f := range p.Effect.Obligations.MFAFactors {
				row.AllowedFactors = append(row.AllowedFactors, f.Type)
			}
		}
		rows = append(rows, row)
	}
	return &PolicyInventory{AuthPolicies: rows}
}

func buildAuditLog(events []jumpcloud.DirectoryInsightsEvent) *AuditLog {
	countByType := make(map[string]int)
	rows := make([]AuditEventRow, 0, len(events))

	for _, e := range events {
		countByType[e.EventType]++
		actor := ""
		if e.InitiatedBy != nil {
			actor = e.InitiatedBy.Email
		}
		rows = append(rows, AuditEventRow{
			EventType: e.EventType,
			Timestamp: e.Timestamp,
			Actor:     actor,
		})
	}

	kept, truncated, dropped := truncateAuditEvents(rows)
	return &AuditLog{
		WindowDays:       auditWindowDays,
		CountByType:      countByType,
		Events:           kept,
		Truncated:        truncated,
		TruncatedDropped: dropped,
	}
}

// --- Helpers ---

func activeUserCount(users []jumpcloud.SystemUser) int {
	count := 0
	for _, u := range users {
		if canSignIn(u) {
			count++
		}
	}
	return count
}

// pct is num out of denom as a percentage with two decimals, or nil when
// denom is 0.
func pct(num, denom int) *float64 {
	if denom == 0 {
		return nil
	}
	v := round2(float64(num) / float64(denom) * 100)
	return &v
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}

func normalizeOS(os string) string {
	switch {
	case os == "":
		return ""
	case containsAny(os, "Mac", "mac", "darwin"):
		return "macOS"
	case containsAny(os, "Windows", "windows"):
		return "Windows"
	case containsAny(os, "Linux", "linux", "Ubuntu", "ubuntu", "CentOS", "centos", "Debian", "debian"):
		return "Linux"
	default:
		return os
	}
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

func appDisplayName(a jumpcloud.Application) string {
	if a.DisplayLabel != "" {
		return a.DisplayLabel
	}
	if a.DisplayName != "" {
		return a.DisplayName
	}
	return a.Name
}
