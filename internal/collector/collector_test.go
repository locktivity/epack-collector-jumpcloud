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
			{ID: "a1", Email: "admin@co.com", TOTPEnabled: true, RoleName: "Administrator"},
			{ID: "a2", Email: "admin2@co.com", TOTPEnabled: false, RoleName: "Administrator With Billing"},
		},
		systems: []jumpcloud.System{
			{ID: "s1", Hostname: "mac-1", OS: "Mac OS X", Active: true,
				MDM: &jumpcloud.SystemMDM{Internal: &jumpcloud.MDMInternal{DeviceID: "dev1"}}},
			{ID: "s2", Hostname: "win-1", OS: "Windows", Active: true},
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
				Effect: &jumpcloud.AuthPolicyEffect{Action: "allow"},
				Conditions: &jumpcloud.AuthPolicyConditions{
					DeviceManaged: &jumpcloud.BoolCondition{Value: true},
				},
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
	if posture.Users.Suspended != 1 {
		t.Errorf("users.suspended = %d, want 1", posture.Users.Suspended)
	}
	if posture.Users.Locked != 1 {
		t.Errorf("users.locked = %d, want 1", posture.Users.Locked)
	}

	if posture.Authentication.MFACoveragePct < 66 || posture.Authentication.MFACoveragePct > 67 {
		t.Errorf("mfa_coverage_pct = %v, want ~66.67", posture.Authentication.MFACoveragePct)
	}
	if posture.Authentication.WebAuthnEnrolledPct < 33 || posture.Authentication.WebAuthnEnrolledPct > 34 {
		t.Errorf("webauthn_enrolled_pct = %v, want ~33.33", posture.Authentication.WebAuthnEnrolledPct)
	}

	if posture.Admins == nil {
		t.Fatal("admins should be present")
	}
	if posture.Admins.TotalAdmins != 2 {
		t.Errorf("admins.total = %d, want 2", posture.Admins.TotalAdmins)
	}
	if posture.Admins.SuperAdminCount != 1 {
		t.Errorf("admins.super_admin_count = %d, want 1 (only 'Administrator' role)", posture.Admins.SuperAdminCount)
	}
	if posture.Admins.AdminMFACoveragePct != 50 {
		t.Errorf("admin_mfa_coverage_pct = %v, want 50", posture.Admins.AdminMFACoveragePct)
	}

	if posture.Apps == nil {
		t.Fatal("apps should be present")
	}
	if posture.Apps.TotalApps != 3 {
		t.Errorf("apps.total = %d, want 3", posture.Apps.TotalApps)
	}
	if posture.Apps.SSOEnabledApps != 2 {
		t.Errorf("apps.sso_enabled = %d, want 2", posture.Apps.SSOEnabledApps)
	}

	if posture.Policies == nil {
		t.Fatal("policies should be present")
	}
	if !posture.Policies.HasMFARequiredPolicy {
		t.Error("policies.has_mfa_required_policy should be true")
	}
	if !posture.Policies.HasDeviceManagedCondition {
		t.Error("policies.has_device_managed_condition should be true")
	}
	if !posture.Policies.HasPhishingResistantAdminPolicy {
		t.Error("policies.has_phishing_resistant_admin_policy should be true")
	}

	if posture.Devices == nil {
		t.Fatal("devices should be present")
	}
	if posture.Devices.TotalSystems != 3 {
		t.Errorf("devices.total = %d, want 3", posture.Devices.TotalSystems)
	}
	if posture.Devices.MDMEnrolled != 1 {
		t.Errorf("devices.mdm_enrolled = %d, want 1", posture.Devices.MDMEnrolled)
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
		t.Fatal("app_inventory should be present at audit level")
	}
	if posture.DeviceInventory == nil {
		t.Fatal("device_inventory should be present at audit level")
	}
	if posture.GroupInventory == nil {
		t.Fatal("group_inventory should be present at audit level")
	}
	if posture.PolicyInventory == nil {
		t.Fatal("policy_inventory should be present at audit level")
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
	if len(posture.AuditLog.Events) != 2 {
		t.Errorf("events count = %d, want 2", len(posture.AuditLog.Events))
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

	if posture.Users.Total != 1 {
		t.Errorf("users.total = %d, want 1", posture.Users.Total)
	}
	// Unavailable surfaces should be nil, not zero-valued
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
	if posture.Diagnostics == nil {
		t.Fatal("diagnostics should be present")
	}
	if len(posture.Diagnostics.PermissionErrors) < 4 {
		t.Errorf("expected at least 4 permission errors, got %d", len(posture.Diagnostics.PermissionErrors))
	}
}

func TestCollect_CancellationPropagates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	mock := &mockClient{
		usersErr: context.Canceled,
	}
	c := New(Config{}, mock)
	_, err := c.Collect(ctx, componentsdk.LevelTrust)
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
}

func TestCollect_UnauthorizedIsFatal(t *testing.T) {
	mock := &mockClient{
		users:     []jumpcloud.SystemUser{{ID: "u1", Username: "alice", State: "ACTIVATED"}},
		appsErr:   &jumpcloud.APIError{StatusCode: 401},
	}
	c := New(Config{}, mock)
	_, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err == nil {
		t.Fatal("expected fatal error from 401")
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

	for _, field := range []string{
		"schema_version", "collected_at", "collected_at_level",
		"users", "authentication",
	} {
		if _, ok := decoded[field]; !ok {
			t.Errorf("missing required top-level field: %s", field)
		}
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
		t.Fatal("app_security should be present")
	}

	if idp.PrivilegedAccess == nil {
		t.Fatal("privileged_access should be present")
	}
	if idp.PrivilegedAccess.SuperAdminCount != 1 {
		t.Errorf("super_admin_count = %d, want 1", idp.PrivilegedAccess.SuperAdminCount)
	}

	if idp.Policy == nil {
		t.Fatal("policy should be present")
	}
	if !idp.Policy.MFARequired {
		t.Error("mfa_required should be true (policy exists that requires MFA)")
	}

	if idp.DeviceAccess == nil {
		t.Fatal("device_access should be present")
	}
}

func TestToIDPPosture_UnavailableSections(t *testing.T) {
	posture := &OrgPosture{
		Users: UserMetrics{Total: 1, Active: 1},
		Authentication: AuthenticationMetrics{MFACoveragePct: 100},
		// Apps, Admins, Policies, Devices are nil (unavailable)
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
	if idp.Policy != nil {
		t.Error("policy should be nil when policies unavailable")
	}
	if idp.DeviceAccess != nil {
		t.Error("device_access should be nil when policies unavailable")
	}
}

func TestToIDPPosture_NoUsers(t *testing.T) {
	posture := &OrgPosture{}
	if idp := posture.ToIDPPosture(); idp != nil {
		t.Error("ToIDPPosture() should return nil when there are no users")
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
				t.Errorf("isPhishingResistantOnly() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsSuperAdmin(t *testing.T) {
	tests := []struct {
		role string
		want bool
	}{
		{"Administrator", true},
		{"Administrator With Billing", false},
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
