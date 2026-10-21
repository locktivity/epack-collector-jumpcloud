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
	users        []jumpcloud.SystemUser
	userTotal    int
	usersErr     error
	apps         []jumpcloud.Application
	appTotal     int
	appsErr      error
	org          *jumpcloud.Organization
	orgErr       error
	admins       []jumpcloud.Administrator
	adminTotal   int
	adminsErr    error
	systems      []jumpcloud.System
	sysTotal     int
	systemsErr   error
	userGroups   []jumpcloud.UserGroup
	ugCapped     bool
	userGroupErr error
	sysGroups    []jumpcloud.SystemGroup
	sgCapped     bool
	sysGroupErr  error
	authPolicies []jumpcloud.AuthPolicy
	polCapped    bool
	policyErr    error
	events       []jumpcloud.DirectoryInsightsEvent
	eventsErr    error

	bitlocker       []jumpcloud.InsightBitLocker
	bitlockerCapped bool
	bitlockerErr    error
	alf             []jumpcloud.InsightALF
	alfErr          error
	wsc             []jumpcloud.InsightWindowsSecurityCenter
	wscErr          error
	products        []jumpcloud.InsightWindowsSecurityProduct
	productsErr     error
	insightUsers    []jumpcloud.InsightUser
	insightUsersErr error
	insightCalls    []string
}

func (m *mockClient) ListBitLockerInfo(ctx context.Context) ([]jumpcloud.InsightBitLocker, bool, error) {
	m.insightCalls = append(m.insightCalls, "bitlocker_info")
	return m.bitlocker, m.bitlockerCapped, m.bitlockerErr
}
func (m *mockClient) ListALF(ctx context.Context) ([]jumpcloud.InsightALF, bool, error) {
	m.insightCalls = append(m.insightCalls, "alf")
	return m.alf, false, m.alfErr
}
func (m *mockClient) ListWindowsSecurityCenter(ctx context.Context) ([]jumpcloud.InsightWindowsSecurityCenter, bool, error) {
	m.insightCalls = append(m.insightCalls, "windows_security_center")
	return m.wsc, false, m.wscErr
}
func (m *mockClient) ListWindowsSecurityProducts(ctx context.Context) ([]jumpcloud.InsightWindowsSecurityProduct, bool, error) {
	m.insightCalls = append(m.insightCalls, "windows_security_products")
	return m.products, false, m.productsErr
}
func (m *mockClient) ListInsightUsers(ctx context.Context) ([]jumpcloud.InsightUser, bool, error) {
	m.insightCalls = append(m.insightCalls, "users")
	return m.insightUsers, false, m.insightUsersErr
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
func (m *mockClient) GetOrganization(ctx context.Context, orgID string) (*jumpcloud.Organization, error) {
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
func (m *mockClient) ListUserGroups(ctx context.Context) ([]jumpcloud.UserGroup, bool, error) {
	return m.userGroups, m.ugCapped, m.userGroupErr
}
func (m *mockClient) ListSystemGroups(ctx context.Context) ([]jumpcloud.SystemGroup, bool, error) {
	return m.sysGroups, m.sgCapped, m.sysGroupErr
}
func (m *mockClient) ListAuthPolicies(ctx context.Context) ([]jumpcloud.AuthPolicy, bool, error) {
	return m.authPolicies, m.polCapped, m.policyErr
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
			{ID: "a1", Email: "admin@co.com", TOTPEnrolled: true, RoleName: "Administrator With Billing"},
			{ID: "a2", Email: "admin2@co.com", TOTPEnrolled: false, RoleName: "Administrator"},
			{ID: "a3", Email: "helpdesk@co.com", TOTPEnrolled: true, RoleName: "Help Desk"},
		},
		systems: []jumpcloud.System{
			{ID: "s1", Hostname: "mac-1", OS: "Mac OS X", Active: true,
				MDM: &jumpcloud.SystemMDM{Vendor: "internal", Internal: &jumpcloud.MDMInternal{DeviceID: "dev1"}}},
			{ID: "s2", Hostname: "win-1", OS: "Windows", Active: true,
				MDM: &jumpcloud.SystemMDM{Vendor: "internal", Internal: &jumpcloud.MDMInternal{WindowsDeviceID: "win-dev1"}}},
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

	if posture.Users.Total != 4 {
		t.Errorf("users.total = %d, want 4", posture.Users.Total)
	}

	if posture.Admins == nil {
		t.Fatal("admins should be present")
	}
	if posture.Admins.TotalAdmins != 3 {
		t.Errorf("admins.total = %d, want 3", posture.Admins.TotalAdmins)
	}
	// Only "Administrator With Billing" is super-admin
	if posture.Admins.SuperAdminCount != 1 {
		t.Errorf("super_admin_count = %d, want 1", posture.Admins.SuperAdminCount)
	}

	if posture.Devices == nil {
		t.Fatal("devices should be present")
	}
	// mac-1 (internal vendor + deviceId) and win-1 (internal vendor + windowsDeviceId)
	if posture.Devices.MDMEnrolled != 2 {
		t.Errorf("mdm_enrolled = %d, want 2", posture.Devices.MDMEnrolled)
	}

	if posture.Policies == nil {
		t.Fatal("policies should be present")
	}
	if !posture.Policies.HasDeviceManagedCondition {
		t.Error("has_device_managed_condition should be true")
	}

	// Trust level must NOT include inventories
	if posture.UserInventory != nil {
		t.Error("user_inventory must be nil at trust level")
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
	if posture.AuditLog != nil {
		t.Error("audit_log must be nil at audit level")
	}
}

func TestCollect_InternalLevel(t *testing.T) {
	mock := richMock()
	mock.events = []jumpcloud.DirectoryInsightsEvent{
		{EventType: "admin_login", Timestamp: "2024-01-01T00:00:00Z",
			InitiatedBy: &jumpcloud.EventActor{Email: "admin@co.com"}},
	}
	c := New(Config{}, mock)
	posture, err := c.Collect(context.Background(), componentsdk.LevelInternal)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if posture.AuditLog == nil {
		t.Fatal("audit_log should be present at internal level")
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
	if posture.Apps != nil || posture.Admins != nil || posture.Devices != nil || posture.Policies != nil {
		t.Error("unavailable surfaces should be nil")
	}
	if posture.Diagnostics == nil || len(posture.Diagnostics.PermissionErrors) < 4 {
		t.Error("expected at least 4 permission errors")
	}
}

func TestCollect_UnauthorizedIsFatal(t *testing.T) {
	mock := &mockClient{
		users:   []jumpcloud.SystemUser{{ID: "u1", State: "ACTIVATED"}},
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
		users:  []jumpcloud.SystemUser{{ID: "u1", State: "ACTIVATED"}},
		orgErr: &jumpcloud.APIError{StatusCode: 401},
	}
	c := New(Config{}, mock)
	_, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err == nil {
		t.Fatal("expected fatal error from organization 401")
	}
}

func TestCollect_OrgValidationEmptyListWithOrgID(t *testing.T) {
	mock := &mockClient{
		users:  []jumpcloud.SystemUser{{ID: "u1", State: "ACTIVATED"}},
		orgErr: &jumpcloud.OrgValidationError{},
	}
	c := New(Config{OrgID: "tenant-b"}, mock)
	_, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err == nil {
		t.Fatal("expected fatal error when org_id is set but no orgs returned")
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

func TestCollect_V2Capped_EmitsDiagnostic(t *testing.T) {
	mock := richMock()
	mock.ugCapped = true
	mock.sgCapped = true
	mock.polCapped = true

	c := New(Config{}, mock)
	posture, err := c.Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if posture.Diagnostics == nil {
		t.Fatal("diagnostics should be present when V2 lists are capped")
	}
	if len(posture.Diagnostics.Warnings) < 3 {
		t.Errorf("expected at least 3 cap warnings, got %d", len(posture.Diagnostics.Warnings))
	}
}

func TestCollect_MFACoverage_SMSOnly(t *testing.T) {
	mock := &mockClient{
		users: []jumpcloud.SystemUser{
			{ID: "u1", Username: "alice", State: "ACTIVATED",
				MFAEnrollment: &jumpcloud.MFAEnrollment{OverallStatus: "ENROLLED", SMSStatus: "ENROLLED"}},
		},
	}
	c := New(Config{}, mock)
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if posture.Authentication.MFACoveragePct != 100 {
		t.Errorf("mfa_coverage_pct = %v, want 100", posture.Authentication.MFACoveragePct)
	}
}

func TestCollect_MDM_VendorNone(t *testing.T) {
	mock := &mockClient{
		users:   []jumpcloud.SystemUser{{ID: "u1", State: "ACTIVATED"}},
		systems: []jumpcloud.System{{ID: "s1", Hostname: "h", Active: true, MDM: &jumpcloud.SystemMDM{Vendor: "none"}}},
	}
	c := New(Config{}, mock)
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if posture.Devices == nil || posture.Devices.MDMEnrolled != 0 {
		t.Errorf("mdm_enrolled should be 0 for vendor=none")
	}
}

func TestCollect_MDM_VendorUnknown(t *testing.T) {
	mock := &mockClient{
		users:   []jumpcloud.SystemUser{{ID: "u1", State: "ACTIVATED"}},
		systems: []jumpcloud.System{{ID: "s1", Hostname: "h", Active: true, MDM: &jumpcloud.SystemMDM{Vendor: "unknown"}}},
	}
	c := New(Config{}, mock)
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if posture.Devices == nil || posture.Devices.MDMEnrolled != 0 {
		t.Errorf("mdm_enrolled should be 0 for vendor=unknown")
	}
}

func TestCollect_MDM_VendorExternal(t *testing.T) {
	mock := &mockClient{
		users:   []jumpcloud.SystemUser{{ID: "u1", State: "ACTIVATED"}},
		systems: []jumpcloud.System{{ID: "s1", Hostname: "h", Active: true, MDM: &jumpcloud.SystemMDM{Vendor: "external"}}},
	}
	c := New(Config{}, mock)
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if posture.Devices == nil || posture.Devices.MDMEnrolled != 1 {
		t.Errorf("mdm_enrolled should be 1 for vendor=external")
	}
}

func TestCollect_PartialDiscovery(t *testing.T) {
	mock := richMock()
	mock.userTotal = 100
	mock.appTotal = 50

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

func TestToIDPPosture_Complete(t *testing.T) {
	c := New(Config{}, richMock())
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	idp := posture.ToIDPPosture()
	if idp == nil {
		t.Fatal("should not be nil for complete data")
	}
	if idp.Provider != "jumpcloud" {
		t.Errorf("provider = %q", idp.Provider)
	}
	if idp.AppSecurity == nil {
		t.Error("app_security should be present")
	}
	if idp.PrivilegedAccess == nil {
		t.Fatal("privileged_access should be present")
	}
	if idp.PrivilegedAccess.SuperAdminCount != 1 {
		t.Errorf("super_admin_count = %d, want 1", idp.PrivilegedAccess.SuperAdminCount)
	}
}

func TestToIDPPosture_PartialUsersReturnsNil(t *testing.T) {
	posture := &OrgPosture{
		Users:          UserMetrics{Total: 100, Active: 100, Partial: true},
		Authentication: AuthenticationMetrics{MFACoveragePct: 100},
		Apps:           &AppMetrics{TotalApps: 5, SSOEnabledApps: 5},
		Admins:         &AdminMetrics{TotalAdmins: 1, SuperAdminCount: 1},
	}
	if idp := posture.ToIDPPosture(); idp != nil {
		t.Error("should return nil when users are partial")
	}
}

func TestToIDPPosture_NoEnforcementClaims(t *testing.T) {
	posture := &OrgPosture{
		Users:          UserMetrics{Total: 1, Active: 1},
		Authentication: AuthenticationMetrics{MFACoveragePct: 100},
		Policies:       &PolicyMetrics{HasMFARequiredPolicy: true},
	}
	idp := posture.ToIDPPosture()
	data, _ := json.Marshal(idp)
	var raw map[string]any
	_ = json.Unmarshal(data, &raw)
	if _, ok := raw["policy"]; ok {
		t.Error("must not contain policy")
	}
	if _, ok := raw["device_access"]; ok {
		t.Error("must not contain device_access")
	}
}

func TestToIDPPosture_NoUsers(t *testing.T) {
	posture := &OrgPosture{}
	if posture.ToIDPPosture() != nil {
		t.Error("should return nil for zero users")
	}
}

func TestConditionHasDeviceManaged(t *testing.T) {
	tests := []struct {
		name string
		cond json.RawMessage
		want bool
	}{
		{"boolean true", json.RawMessage(`{"deviceManaged":true}`), true},
		{"boolean false", json.RawMessage(`{"deviceManaged":false}`), false},
		{"nested in all", json.RawMessage(`{"all":[{"deviceManaged":true}]}`), true},
		{"nested in not", json.RawMessage(`{"not":{"deviceManaged":true}}`), true},
		{"absent", json.RawMessage(`{"ipAddressIn":["10.0.0.0/8"]}`), false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := jumpcloud.AuthPolicy{Conditions: tt.cond}
			if got := p.ConditionHasDeviceManaged(); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPhishingResistantOnly(t *testing.T) {
	tests := []struct {
		name    string
		factors []jumpcloud.MFAFactorEntry
		want    bool
	}{
		{"empty", nil, false},
		{"webauthn only", []jumpcloud.MFAFactorEntry{{Type: "WEBAUTHN"}}, true},
		{"mixed", []jumpcloud.MFAFactorEntry{{Type: "WEBAUTHN"}, {Type: "TOTP"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPhishingResistantOnly(tt.factors); got != tt.want {
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
		{"Administrator", false},
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
		input, want string
	}{
		{"Mac OS X", "macOS"}, {"Windows 10", "Windows"}, {"Ubuntu 22.04", "Linux"}, {"", ""}, {"ChromeOS", "ChromeOS"},
	}
	for _, tt := range tests {
		if got := normalizeOS(tt.input); got != tt.want {
			t.Errorf("normalizeOS(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
