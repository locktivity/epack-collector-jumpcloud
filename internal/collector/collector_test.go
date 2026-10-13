package collector

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-jumpcloud/internal/jumpcloud"
	"github.com/locktivity/epack/componentsdk"
)

type mockClient struct {
	users          []jumpcloud.SystemUser
	userTotal      int
	usersErr       error
	apps           []jumpcloud.Application
	appTotal       int
	appsErr        error
	org            *jumpcloud.Organization
	orgErr         error
	admins         []jumpcloud.Administrator
	adminTotal     int
	adminsErr      error
	systems        []jumpcloud.System
	sysTotal       int
	systemsErr     error
	userGroups     []jumpcloud.UserGroup
	userGroupErr   error
	sysGroups      []jumpcloud.SystemGroup
	sysGroupErr    error
	authPolicies   []jumpcloud.AuthPolicy
	policyErr      error
	events         []jumpcloud.DirectoryInsightsEvent
	eventsErr      error
}

func (m *mockClient) ListSystemUsers(ctx context.Context) ([]jumpcloud.SystemUser, int, error) {
	total := m.userTotal
	if total == 0 {
		total = len(m.users)
	}
	return m.users, total, m.usersErr
}
func (m *mockClient) ListApplications(ctx context.Context) ([]jumpcloud.Application, int, error) {
	total := m.appTotal
	if total == 0 {
		total = len(m.apps)
	}
	return m.apps, total, m.appsErr
}
func (m *mockClient) GetOrganization(ctx context.Context) (*jumpcloud.Organization, error) {
	return m.org, m.orgErr
}
func (m *mockClient) ListAdministrators(ctx context.Context) ([]jumpcloud.Administrator, int, error) {
	total := m.adminTotal
	if total == 0 {
		total = len(m.admins)
	}
	return m.admins, total, m.adminsErr
}
func (m *mockClient) ListSystems(ctx context.Context) ([]jumpcloud.System, int, error) {
	total := m.sysTotal
	if total == 0 {
		total = len(m.systems)
	}
	return m.systems, total, m.systemsErr
}
func (m *mockClient) ListUserGroups(ctx context.Context) ([]jumpcloud.UserGroup, error) {
	return m.userGroups, m.userGroupErr
}
func (m *mockClient) ListSystemGroups(ctx context.Context) ([]jumpcloud.SystemGroup, error) {
	return m.sysGroups, m.sysGroupErr
}
func (m *mockClient) ListAuthPolicies(ctx context.Context) ([]jumpcloud.AuthPolicy, error) {
	return m.authPolicies, m.policyErr
}
func (m *mockClient) QueryEvents(ctx context.Context, service string, start, end time.Time, limit int) ([]jumpcloud.DirectoryInsightsEvent, error) {
	return m.events, m.eventsErr
}

func richMock() *mockClient {
	return &mockClient{
		users: []jumpcloud.SystemUser{
			{ID: "u1", Username: "alice", Email: "alice@co.com", State: "ACTIVATED",
				TOTPEnabled: true,
				MFAEnrollment: &jumpcloud.MFAEnrollment{
					OverallStatus:  "ENROLLED",
					TOTPStatus:     "ENROLLED",
					WebAuthnStatus: "ENROLLED",
				}},
			{ID: "u2", Username: "bob", Email: "bob@co.com", State: "ACTIVATED",
				TOTPEnabled: true,
				MFAEnrollment: &jumpcloud.MFAEnrollment{
					OverallStatus:  "ENROLLED",
					TOTPStatus:     "ENROLLED",
					WebAuthnStatus: "NOT_ENROLLED",
				}},
			{ID: "u3", Username: "charlie", Email: "charlie@co.com", State: "SUSPENDED"},
			{ID: "u4", Username: "dave", Email: "dave@co.com", State: "ACTIVATED", AccountLocked: true},
		},
		apps: []jumpcloud.Application{
			{ID: "app1", Name: "slack", DisplayName: "Slack", SSO: &jumpcloud.ApplicationSSO{Type: "saml"}},
			{ID: "app2", Name: "jira", DisplayName: "Jira", SSO: &jumpcloud.ApplicationSSO{Type: "oidc"}},
			{ID: "app3", Name: "custom", DisplayName: "Custom App"},
		},
		org: &jumpcloud.Organization{ID: "org-1", DisplayName: "Test Org"},
		admins: []jumpcloud.Administrator{
			{ID: "a1", Email: "admin@co.com", TOTPEnabled: true, RoleName: "Administrator With Billing"},
			{ID: "a2", Email: "admin2@co.com", TOTPEnabled: false, RoleName: "Help Desk"},
		},
		systems: []jumpcloud.System{
			{ID: "s1", Hostname: "mac-1", OS: "Mac OS X", Active: true,
				MDM: &jumpcloud.SystemMDM{Internal: &jumpcloud.MDMInternal{DeviceID: "dev1"}}},
			{ID: "s2", Hostname: "win-1", OS: "Windows", Active: true,
				MDM: &jumpcloud.SystemMDM{Internal: &jumpcloud.MDMInternal{WindowsDeviceID: "win-dev1"}}},
			{ID: "s3", Hostname: "linux-1", OS: "Ubuntu", Active: false},
		},
		authPolicies: []jumpcloud.AuthPolicy{
			{
				ID: "p1", Name: "User Portal MFA", Type: "user_portal",
				Effect: &jumpcloud.AuthPolicyEffect{
					Action: "allow",
					Obligations: &jumpcloud.PolicyObligations{
						MFA: &jumpcloud.PolicyMFA{Required: true},
					},
				},
			},
			{
				ID: "p2", Name: "Admin Portal Phishing Resistant", Type: "admin_portal",
				Effect: &jumpcloud.AuthPolicyEffect{
					Action: "allow",
					Obligations: &jumpcloud.PolicyObligations{
						MFA:        &jumpcloud.PolicyMFA{Required: true},
						MFAFactors: []jumpcloud.MFAFactorEntry{{Type: "WEBAUTHN"}, {Type: "FIDO2"}},
					},
				},
			},
			{
				ID: "p3", Name: "Device Managed SSO", Type: "sso",
				Effect:     &jumpcloud.AuthPolicyEffect{Action: "allow"},
				Conditions: json.RawMessage(`{"deviceManaged":true}`),
			},
		},
		userGroups: []jumpcloud.UserGroup{{ID: "ug1", Name: "Engineering", Type: "user_group"}},
		sysGroups:  []jumpcloud.SystemGroup{{ID: "sg1", Name: "Workstations", Type: "system_group"}},
	}
}

func TestCollect_TrustLevel(t *testing.T) {
	c := New(Config{}, richMock())
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if posture.SchemaVersion != SchemaVersion {
		t.Errorf("schema_version = %q, want %q", posture.SchemaVersion, SchemaVersion)
	}
	if posture.Users.Total != 4 {
		t.Errorf("users.total = %d, want 4", posture.Users.Total)
	}
	if posture.Users.Active != 3 {
		t.Errorf("users.active = %d, want 3", posture.Users.Active)
	}
	if posture.Authentication.MFACoveragePct < 66 || posture.Authentication.MFACoveragePct > 67 {
		t.Errorf("mfa_coverage_pct = %v, want ~66.67", posture.Authentication.MFACoveragePct)
	}

	if posture.Admins == nil {
		t.Fatal("admins should be present")
	}
	if posture.Admins.TotalAdmins != 2 {
		t.Errorf("admins.total = %d, want 2", posture.Admins.TotalAdmins)
	}
	// Administrator With Billing is the highest role; Help Desk is not super-admin
	if posture.Admins.SuperAdminCount != 1 {
		t.Errorf("super_admin_count = %d, want 1", posture.Admins.SuperAdminCount)
	}

	if posture.Apps == nil {
		t.Fatal("apps should be present")
	}
	if posture.Apps.SSOEnabledApps != 2 {
		t.Errorf("apps.sso_enabled = %d, want 2", posture.Apps.SSOEnabledApps)
	}

	if posture.Policies == nil {
		t.Fatal("policies should be present")
	}
	if !posture.Policies.HasMFARequiredPolicy {
		t.Error("has_mfa_required_policy should be true")
	}
	if !posture.Policies.HasDeviceManagedCondition {
		t.Error("has_device_managed_condition should be true")
	}
	if !posture.Policies.HasPhishingResistantAdminPolicy {
		t.Error("has_phishing_resistant_admin_policy should be true")
	}

	if posture.Devices == nil {
		t.Fatal("devices should be present")
	}
	if posture.Devices.TotalSystems != 3 {
		t.Errorf("devices.total = %d, want 3", posture.Devices.TotalSystems)
	}
	// mac-1 has deviceId, win-1 has windowsDeviceId
	if posture.Devices.MDMEnrolled != 2 {
		t.Errorf("devices.mdm_enrolled = %d, want 2", posture.Devices.MDMEnrolled)
	}

	// Trust level must NOT include inventories or audit log
	if posture.UserInventory != nil {
		t.Error("user_inventory must be nil at trust level")
	}
	if posture.AppInventory != nil {
		t.Error("app_inventory must be nil at trust level")
	}
	if posture.DeviceInventory != nil {
		t.Error("device_inventory must be nil at trust level")
	}
	if posture.GroupInventory != nil {
		t.Error("group_inventory must be nil at trust level")
	}
	if posture.PolicyInventory != nil {
		t.Error("policy_inventory must be nil at trust level")
	}
	if posture.AuditLog != nil {
		t.Error("audit_log must be nil at trust level")
	}
}

func TestCollect_AuditLevel(t *testing.T) {
	c := New(Config{}, richMock())
	posture, err := c.Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if posture.UserInventory == nil {
		t.Fatal("user_inventory should be present at audit level")
	}
	if len(posture.UserInventory.PerUser) != 4 {
		t.Errorf("user_inventory count = %d, want 4", len(posture.UserInventory.PerUser))
	}
	if posture.AppInventory == nil {
		t.Fatal("app_inventory should be present")
	}
	if posture.PolicyInventory == nil {
		t.Fatal("policy_inventory should be present")
	}
	if posture.AuditLog != nil {
		t.Error("audit_log must be nil at audit level")
	}
}

func TestCollect_InternalLevel(t *testing.T) {
	mock := richMock()
	mock.events = []jumpcloud.DirectoryInsightsEvent{
		{EventType: "admin_login", Timestamp: "2024-01-01T00:00:00Z",
			InitiatedBy: &jumpcloud.EventActor{Email: "admin@co.com"}},
		{EventType: "user_login", Timestamp: "2024-01-01T00:00:00Z"},
	}

	c := New(Config{}, mock)
	posture, err := c.Collect(context.Background(), componentsdk.LevelInternal)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if posture.AuditLog == nil {
		t.Fatal("audit_log should be present at internal level")
	}
	if posture.AuditLog.WindowDays != 7 {
		t.Errorf("window_days = %d, want 7", posture.AuditLog.WindowDays)
	}
	if posture.UserInventory == nil {
		t.Error("user_inventory should be present at internal level")
	}
}

func TestCollect_PermissionDegradation(t *testing.T) {
	mock := &mockClient{
		users:      []jumpcloud.SystemUser{{ID: "u1", Username: "alice", State: "ACTIVATED"}},
		appsErr:    &jumpcloud.APIError{StatusCode: 403},
		adminsErr:  &jumpcloud.APIError{StatusCode: 403},
		systemsErr: &jumpcloud.APIError{StatusCode: 403},
		policyErr:  &jumpcloud.APIError{StatusCode: 403},
	}

	c := New(Config{}, mock)
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if posture.Apps != nil {
		t.Error("apps should be nil when permission denied")
	}
	if posture.Admins != nil {
		t.Error("admins should be nil when permission denied")
	}
	if posture.Devices != nil {
		t.Error("devices should be nil when permission denied")
	}
	if posture.Policies != nil {
		t.Error("policies should be nil when permission denied")
	}
	if posture.Diagnostics == nil || len(posture.Diagnostics.PermissionErrors) < 4 {
		t.Errorf("expected at least 4 permission errors")
	}
}

func TestCollect_CancellationPropagates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	mock := &mockClient{usersErr: context.Canceled}
	c := New(Config{}, mock)
	_, err := c.Collect(ctx, componentsdk.LevelTrust)
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
}

func TestCollect_UnauthorizedIsFatal(t *testing.T) {
	mock := &mockClient{
		users:   []jumpcloud.SystemUser{{ID: "u1", Username: "alice", State: "ACTIVATED"}},
		appsErr: &jumpcloud.APIError{StatusCode: 401},
	}
	c := New(Config{}, mock)
	_, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err == nil {
		t.Fatal("expected fatal error from 401")
	}
}

func TestCollect_OrganizationUnauthorizedIsFatal(t *testing.T) {
	mock := &mockClient{
		users:  []jumpcloud.SystemUser{{ID: "u1", Username: "alice", State: "ACTIVATED"}},
		orgErr: &jumpcloud.APIError{StatusCode: 401},
	}
	c := New(Config{}, mock)
	_, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err == nil {
		t.Fatal("expected fatal error from organization 401")
	}
}

func TestCollect_MFACoverage_SMSOnly(t *testing.T) {
	mock := &mockClient{
		users: []jumpcloud.SystemUser{
			{ID: "u1", Username: "alice", State: "ACTIVATED",
				MFAEnrollment: &jumpcloud.MFAEnrollment{
					OverallStatus: "ENROLLED",
					SMSStatus:     "ENROLLED",
				}},
		},
	}

	c := New(Config{}, mock)
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if posture.Authentication.MFACoveragePct != 100 {
		t.Errorf("mfa_coverage_pct = %v, want 100 (SMS counts as MFA)", posture.Authentication.MFACoveragePct)
	}
	if posture.Authentication.WebAuthnEnrolledPct != 0 {
		t.Errorf("webauthn_enrolled_pct = %v, want 0 (SMS is not phishing-resistant)", posture.Authentication.WebAuthnEnrolledPct)
	}
}

func TestCollect_MDM_WindowsDeviceID(t *testing.T) {
	mock := &mockClient{
		users: []jumpcloud.SystemUser{{ID: "u1", State: "ACTIVATED"}},
		systems: []jumpcloud.System{
			{ID: "s1", Hostname: "win-1", OS: "Windows", Active: true,
				MDM: &jumpcloud.SystemMDM{
					Vendor:   "internal",
					Internal: &jumpcloud.MDMInternal{WindowsDeviceID: "win-dev1"},
				}},
		},
	}
	c := New(Config{}, mock)
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if posture.Devices == nil || posture.Devices.MDMEnrolled != 1 {
		t.Errorf("mdm_enrolled = %v, want 1 (windowsDeviceId present)", posture.Devices)
	}
}

func TestCollect_MDM_VendorOnly(t *testing.T) {
	mock := &mockClient{
		users: []jumpcloud.SystemUser{{ID: "u1", State: "ACTIVATED"}},
		systems: []jumpcloud.System{
			{ID: "s1", Hostname: "mac-1", OS: "Mac OS X", Active: true,
				MDM: &jumpcloud.SystemMDM{Vendor: "jamf"}},
		},
	}
	c := New(Config{}, mock)
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if posture.Devices == nil || posture.Devices.MDMEnrolled != 1 {
		t.Errorf("mdm_enrolled should be 1 (third-party vendor present)")
	}
}

func TestCollect_PartialDiscovery(t *testing.T) {
	mock := richMock()
	mock.userTotal = 100 // server says 100 but only 4 returned
	mock.appTotal = 50   // server says 50 but only 3 returned

	c := New(Config{}, mock)
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !posture.Users.Partial {
		t.Error("users.partial should be true")
	}
	if posture.Apps == nil || !posture.Apps.Partial {
		t.Error("apps.partial should be true")
	}
}

func TestCollect_EmptyOrg(t *testing.T) {
	mock := &mockClient{users: []jumpcloud.SystemUser{}}
	c := New(Config{}, mock)
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if posture.Users.Total != 0 {
		t.Errorf("users.total = %d, want 0", posture.Users.Total)
	}
}

func TestCollect_ValidJSON(t *testing.T) {
	c := New(Config{}, richMock())
	posture, err := c.Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := json.Marshal(posture)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}

func TestToIDPPosture(t *testing.T) {
	c := New(Config{}, richMock())
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	idp := posture.ToIDPPosture()
	if idp == nil {
		t.Fatal("ToIDPPosture() returned nil")
	}
	if idp.Provider != "jumpcloud" {
		t.Errorf("provider = %q, want jumpcloud", idp.Provider)
	}
	if idp.UserSecurity.MFACoveragePct < 66 || idp.UserSecurity.MFACoveragePct > 67 {
		t.Errorf("mfa_coverage_pct = %v, want ~66.67", idp.UserSecurity.MFACoveragePct)
	}
	if idp.AppSecurity == nil {
		t.Fatal("app_security should be present (complete data)")
	}
	if idp.PrivilegedAccess == nil {
		t.Fatal("privileged_access should be present (complete data)")
	}
	if idp.PrivilegedAccess.SuperAdminCount != 1 {
		t.Errorf("super_admin_count = %d, want 1", idp.PrivilegedAccess.SuperAdminCount)
	}
}

func TestToIDPPosture_OmitsPartialSections(t *testing.T) {
	posture := &OrgPosture{
		Users:          UserMetrics{Total: 10, Active: 10, Partial: true},
		Authentication: AuthenticationMetrics{MFACoveragePct: 50},
		Apps:           &AppMetrics{TotalApps: 5, SSOEnabledApps: 3, Partial: false},
		Admins:         &AdminMetrics{TotalAdmins: 2, SuperAdminCount: 1, Partial: false},
	}

	idp := posture.ToIDPPosture()
	if idp == nil {
		t.Fatal("should not be nil with 10 users")
	}
	// Partial user discovery => omit sections that depend on complete user counts
	if idp.AppSecurity != nil {
		t.Error("app_security should be nil when users are partial")
	}
	if idp.PrivilegedAccess != nil {
		t.Error("privileged_access should be nil when users are partial")
	}
}

func TestToIDPPosture_OmitsPartialApps(t *testing.T) {
	posture := &OrgPosture{
		Users:          UserMetrics{Total: 1, Active: 1},
		Authentication: AuthenticationMetrics{MFACoveragePct: 100},
		Apps:           &AppMetrics{TotalApps: 5, Partial: true},
		Admins:         &AdminMetrics{TotalAdmins: 1, SuperAdminCount: 1},
	}

	idp := posture.ToIDPPosture()
	if idp.AppSecurity != nil {
		t.Error("app_security should be nil when apps are partial")
	}
	if idp.PrivilegedAccess == nil {
		t.Error("privileged_access should be present (admins complete)")
	}
}

func TestToIDPPosture_NoEnforcementClaims(t *testing.T) {
	posture := &OrgPosture{
		Users:          UserMetrics{Total: 1, Active: 1},
		Authentication: AuthenticationMetrics{MFACoveragePct: 100},
		Policies:       &PolicyMetrics{HasMFARequiredPolicy: true, HasDeviceManagedCondition: true},
	}

	idp := posture.ToIDPPosture()
	if idp == nil {
		t.Fatal("should not be nil")
	}
	// Policy and DeviceAccess should NOT appear in normalized output
	data, _ := json.Marshal(idp)
	var raw map[string]any
	_ = json.Unmarshal(data, &raw)
	if _, ok := raw["policy"]; ok {
		t.Error("normalized output must not contain policy enforcement claims")
	}
	if _, ok := raw["device_access"]; ok {
		t.Error("normalized output must not contain device_access enforcement claims")
	}
}

func TestToIDPPosture_UnavailableSections(t *testing.T) {
	posture := &OrgPosture{
		Users:          UserMetrics{Total: 1, Active: 1},
		Authentication: AuthenticationMetrics{MFACoveragePct: 100},
	}

	idp := posture.ToIDPPosture()
	if idp == nil {
		t.Fatal("should not be nil with 1 user")
	}
	if idp.AppSecurity != nil {
		t.Error("app_security should be nil when apps unavailable")
	}
	if idp.PrivilegedAccess != nil {
		t.Error("privileged_access should be nil when admins unavailable")
	}
}

func TestToIDPPosture_NoUsers(t *testing.T) {
	posture := &OrgPosture{}
	if idp := posture.ToIDPPosture(); idp != nil {
		t.Error("ToIDPPosture() should return nil when there are no users")
	}
}

func TestConditionHasDeviceManaged_BooleanTrue(t *testing.T) {
	p := jumpcloud.AuthPolicy{Conditions: json.RawMessage(`{"deviceManaged":true}`)}
	if !p.ConditionHasDeviceManaged() {
		t.Error("should detect deviceManaged:true")
	}
}

func TestConditionHasDeviceManaged_BooleanFalse(t *testing.T) {
	p := jumpcloud.AuthPolicy{Conditions: json.RawMessage(`{"deviceManaged":false}`)}
	if p.ConditionHasDeviceManaged() {
		t.Error("should not detect deviceManaged:false")
	}
}

func TestConditionHasDeviceManaged_NestedInAll(t *testing.T) {
	p := jumpcloud.AuthPolicy{Conditions: json.RawMessage(`{"all":[{"deviceManaged":true},{"ipAddressIn":["10.0.0.0/8"]}]}`)}
	if !p.ConditionHasDeviceManaged() {
		t.Error("should detect deviceManaged nested in all")
	}
}

func TestConditionHasDeviceManaged_NestedInNot(t *testing.T) {
	p := jumpcloud.AuthPolicy{Conditions: json.RawMessage(`{"not":{"deviceManaged":true}}`)}
	if !p.ConditionHasDeviceManaged() {
		t.Error("should detect deviceManaged nested in not (condition exists)")
	}
}

func TestConditionHasDeviceManaged_Absent(t *testing.T) {
	p := jumpcloud.AuthPolicy{Conditions: json.RawMessage(`{"ipAddressIn":["10.0.0.0/8"]}`)}
	if p.ConditionHasDeviceManaged() {
		t.Error("should not detect absent deviceManaged")
	}
}

func TestConditionHasDeviceManaged_NilConditions(t *testing.T) {
	p := jumpcloud.AuthPolicy{}
	if p.ConditionHasDeviceManaged() {
		t.Error("should not detect on nil conditions")
	}
}

func TestPhishingResistantOnly(t *testing.T) {
	tests := []struct {
		name    string
		factors []jumpcloud.MFAFactorEntry
		want    bool
	}{
		{"empty means any allowed", nil, false},
		{"webauthn only", []jumpcloud.MFAFactorEntry{{Type: "WEBAUTHN"}}, true},
		{"webauthn+fido2 only", []jumpcloud.MFAFactorEntry{{Type: "WEBAUTHN"}, {Type: "FIDO2"}}, true},
		{"mixed with totp", []jumpcloud.MFAFactorEntry{{Type: "WEBAUTHN"}, {Type: "TOTP"}}, false},
		{"totp only", []jumpcloud.MFAFactorEntry{{Type: "TOTP"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPhishingResistantOnly(tt.factors)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsSuperAdmin(t *testing.T) {
	tests := []struct {
		role string
		want bool
	}{
		{"Administrator With Billing", true},
		{"Administrator", true},
		{"Help Desk", false},
		{"Read Only", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := isSuperAdmin(tt.role); got != tt.want {
			t.Errorf("isSuperAdmin(%q) = %v, want %v", tt.role, got, tt.want)
		}
	}
}

func TestNormalizeOS(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Mac OS X", "macOS"},
		{"macOS", "macOS"},
		{"Windows 10", "Windows"},
		{"Ubuntu 22.04", "Linux"},
		{"CentOS 7", "Linux"},
		{"", ""},
		{"ChromeOS", "ChromeOS"},
	}
	for _, tt := range tests {
		got := normalizeOS(tt.input)
		if got != tt.want {
			t.Errorf("normalizeOS(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
