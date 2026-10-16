package collector

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/locktivity/epack-collector-jumpcloud/internal/jumpcloud"
	"github.com/locktivity/epack/componentsdk"
)

const auditWindowDays = 7

// Collect gathers JumpCloud posture data at the requested level.
func (c *Collector) Collect(ctx context.Context, level componentsdk.Level) (*OrgPosture, error) {
	diag := &diagnosticsTracker{}
	now := time.Now().UTC()

	c.status("Fetching users")
	users, serverUserTotal, err := c.client.ListSystemUsers(ctx)
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	userPartial := len(users) < serverUserTotal

	posture := &OrgPosture{
		SchemaVersion:    SchemaVersion,
		CollectedAt:      now.Format(time.RFC3339),
		CollectedAtLevel: string(level),
		Users:            computeUserMetrics(users, userPartial),
		Authentication:   computeAuthMetrics(users),
	}

	c.status("Fetching applications")
	apps, serverAppTotal, appErr := c.client.ListApplications(ctx)
	if appErr != nil {
		if isFatal(appErr) {
			return nil, appErr
		}
		recordSurfaceError(diag, "applications", appErr)
	} else {
		appPartial := len(apps) < serverAppTotal
		posture.Apps = computeAppMetrics(apps, appPartial)
	}

	c.status("Fetching administrators")
	admins, serverAdminTotal, adminErr := c.client.ListAdministrators(ctx)
	if adminErr != nil {
		if isFatal(adminErr) {
			return nil, adminErr
		}
		recordSurfaceError(diag, "administrators", adminErr)
	} else {
		adminPartial := len(admins) < serverAdminTotal
		posture.Admins = computeAdminMetrics(admins, adminPartial)
	}

	c.status("Fetching authentication policies")
	policies, policyCapped, policyErr := c.client.ListAuthPolicies(ctx)
	if policyErr != nil {
		if isFatal(policyErr) {
			return nil, policyErr
		}
		recordSurfaceError(diag, "auth_policies", policyErr)
	} else {
		if policyCapped {
			diag.surfaceWarning("auth_policies", "results capped at internal limit; policy inventory may be incomplete")
		}
		posture.Policies = computePolicyMetrics(policies)
	}

	c.status("Fetching systems")
	systems, serverSysTotal, sysErr := c.client.ListSystems(ctx)
	if sysErr != nil {
		if isFatal(sysErr) {
			return nil, sysErr
		}
		recordSurfaceError(diag, "systems", sysErr)
	} else {
		sysPartial := len(systems) < serverSysTotal
		posture.Devices = computeDeviceMetrics(systems, sysPartial)
	}

	var endpointIn *endpointInputs
	if sysErr == nil {
		endpointIn = &endpointInputs{
			systems:     systems,
			serverTotal: serverSysTotal,
			level:       level,
			now:         now,
			maxAge:      c.cfg.maxObservationAge(),
		}
		if err := c.fetchEndpointTelemetry(ctx, diag, endpointIn); err != nil {
			return nil, err
		}
	}

	org, orgErr := c.client.GetOrganization(ctx, c.cfg.OrgID)
	if orgErr != nil {
		if isFatal(orgErr) || isOrgValidationError(orgErr) {
			return nil, orgErr
		}
		diag.surfaceWarning("organization", safeDiagError(orgErr))
	} else if org != nil {
		posture.OrgID = org.ID
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if level.AtLeast(componentsdk.LevelAudit) {
		c.status("Building inventories")
		posture.UserInventory = buildUserInventory(users)
		if appErr == nil {
			posture.AppInventory = buildAppInventory(apps)
		}
		if sysErr == nil {
			posture.DeviceInventory = buildDeviceInventory(systems)
		}
		if policyErr == nil {
			posture.PolicyInventory = buildPolicyInventory(policies)
		}

		userGroups, ugCapped, ugErr := c.client.ListUserGroups(ctx)
		if ugErr != nil {
			if isFatal(ugErr) {
				return nil, ugErr
			}
			recordSurfaceError(diag, "user_groups", ugErr)
		} else if ugCapped {
			diag.surfaceWarning("user_groups", "results capped at internal limit; group inventory may be incomplete")
		}
		systemGroups, sgCapped, sgErr := c.client.ListSystemGroups(ctx)
		if sgErr != nil {
			if isFatal(sgErr) {
				return nil, sgErr
			}
			recordSurfaceError(diag, "system_groups", sgErr)
		} else if sgCapped {
			diag.surfaceWarning("system_groups", "results capped at internal limit; group inventory may be incomplete")
		}
		if ugErr == nil || sgErr == nil {
			posture.GroupInventory = buildGroupInventory(userGroups, systemGroups)
		}
	}

	if level.AtLeast(componentsdk.LevelInternal) {
		c.status("Fetching audit events")
		start := now.Add(-auditWindowDays * 24 * time.Hour)
		events, evErr := c.client.QueryEvents(ctx, "directory", start, now, MaxAuditEvents+1)
		if evErr != nil {
			if isFatal(evErr) {
				return nil, evErr
			}
			recordSurfaceError(diag, "audit_log", evErr)
		} else {
			posture.AuditLog = buildAuditLog(events)
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if endpointIn != nil {
		endpointIn.users = users
		endpointIn.orgID = posture.OrgID
		posture.endpoint = buildEndpointPosture(*endpointIn)
	}

	posture.Diagnostics = diag.toDiagnostics()
	return posture, nil
}

// isFatal returns true for errors that should abort collection entirely:
// context cancellation, deadline exceeded, and 401 unauthorized.
func isFatal(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if errors.Is(err, jumpcloud.ErrUnauthorized) {
		return true
	}
	return false
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

func computeAuthMetrics(users []jumpcloud.SystemUser) AuthenticationMetrics {
	if len(users) == 0 {
		return AuthenticationMetrics{}
	}

	var mfaCount, totpCount, webauthnCount, pushCount, notEnrolledCount, portalMFACount int
	for _, u := range users {
		if u.State == "SUSPENDED" || u.State == "STAGED" {
			continue
		}

		hasMFA := false
		if u.MFAEnrollment != nil {
			if u.MFAEnrollment.HasAnyMFA() {
				hasMFA = true
			}
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
			hasMFA = true
		}

		if hasMFA {
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

func computeAdminMetrics(admins []jumpcloud.Administrator, partial bool) *AdminMetrics {
	if len(admins) == 0 {
		return &AdminMetrics{}
	}
	mfaCount := 0
	superCount := 0
	for _, a := range admins {
		if a.TOTPEnabled || a.EnableMultiFactor {
			mfaCount++
		}
		if isSuperAdmin(a.RoleName) {
			superCount++
		}
	}
	return &AdminMetrics{
		TotalAdmins:         len(admins),
		SuperAdminCount:     superCount,
		AdminMFACoveragePct: pct(mfaCount, len(admins)),
		Partial:             partial,
	}
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
		return &AppMetrics{}
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

func computeDeviceMetrics(systems []jumpcloud.System, partial bool) *DeviceMetrics {
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

func buildGroupInventory(userGroups []jumpcloud.UserGroup, systemGroups []jumpcloud.SystemGroup) *GroupInventory {
	inv := &GroupInventory{}
	for _, g := range userGroups {
		inv.UserGroups = append(inv.UserGroups, GroupRow{Name: g.Name, Type: g.Type})
	}
	for _, g := range systemGroups {
		inv.SystemGroups = append(inv.SystemGroups, GroupRow{Name: g.Name, Type: g.Type})
	}
	return inv
}

func buildDeviceInventory(systems []jumpcloud.System) *DeviceInventory {
	rows := make([]DeviceRow, 0, len(systems))
	for _, s := range systems {
		rows = append(rows, DeviceRow{
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
		if u.State != "SUSPENDED" && u.State != "STAGED" {
			count++
		}
	}
	return count
}

func pct(num, denom int) float64 {
	if denom == 0 {
		return 0
	}
	return round2(float64(num) / float64(denom) * 100)
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
