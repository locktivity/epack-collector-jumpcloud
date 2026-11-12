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
	if got := posture.Admins.SuperAdminCount; got == nil || *got != 1 {
		t.Errorf("super_admin_count = %v, want 1", got)
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

// gapAt returns the gap rec holds at path and pointer.
func gapAt(rec *componentsdk.Recorder, path, pointer string) (componentsdk.Gap, bool) {
	for _, g := range rec.Gaps() {
		if g.Path == path && g.Pointer == pointer {
			return g, true
		}
	}
	return componentsdk.Gap{}, false
}

func TestCollect_UnauthorizedSurfaceLeavesAGap(t *testing.T) {
	mock := &mockClient{
		users:   []jumpcloud.SystemUser{{ID: "u1", State: "ACTIVATED"}},
		appsErr: &jumpcloud.APIError{StatusCode: 401},
	}
	rec := &componentsdk.Recorder{}
	posture, err := New(Config{Recorder: rec}, mock).Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if posture.Apps != nil {
		t.Error("apps should be left out")
	}
	if g, ok := gapAt(rec, detailedPath, "/apps"); !ok || g.Code != componentsdk.CodeAuthFailed {
		t.Errorf("gap at /apps = %+v, want auth_failed", g)
	}
}

// From the audit level, a refused organization list leaves org_id and
// org_name out with gaps, and the users' organization names the
// organization. Below it neither is written, and the users' email domain
// names the organization.
func TestCollect_OrganizationRefusedLeavesAGap(t *testing.T) {
	for _, tc := range []struct {
		level  componentsdk.Level
		gap    bool
		domain string
	}{
		{componentsdk.LevelTrust, false, "acme.example"},
		{componentsdk.LevelAudit, true, "org-1"},
	} {
		t.Run(string(tc.level), func(t *testing.T) {
			mock := &mockClient{
				users:  []jumpcloud.SystemUser{{ID: "u1", Email: "pat@acme.example", State: "ACTIVATED", Organization: "org-1"}},
				orgErr: &jumpcloud.APIError{StatusCode: 403},
			}
			rec := &componentsdk.Recorder{}
			posture, err := New(Config{Recorder: rec}, mock).Collect(context.Background(), tc.level)
			if err != nil {
				t.Fatalf("Collect: %v", err)
			}
			if posture.OrgID != "" || posture.OrgName != "" {
				t.Errorf("org_id = %q, org_name = %q; want both left out", posture.OrgID, posture.OrgName)
			}
			for _, pointer := range []string{"/org_id", "/org_name"} {
				if g, ok := gapAt(rec, detailedPath, pointer); ok != tc.gap || ok && g.Code != componentsdk.CodePermissionDenied {
					t.Errorf("gap at %s = %+v, %v; want permission_denied only from the audit level", pointer, g, ok)
				}
			}
			if idp := posture.ToIDPPosture(); idp == nil || idp.OrgDomain != tc.domain {
				t.Errorf("idp-posture = %+v, want org_domain %q", idp, tc.domain)
			}
		})
	}
}

// From the audit level, org_name is the organization's display name. An
// organization with none leaves it out with no gap, and a list with no
// organization leaves it out with an invalid_response gap. Below the audit
// level it is never written and has no gap.
func TestCollect_OrganizationName(t *testing.T) {
	for _, level := range []componentsdk.Level{componentsdk.LevelTrust, componentsdk.LevelAudit} {
		audit := level.AtLeast(componentsdk.LevelAudit)
		for _, tc := range []struct {
			name string
			org  *jumpcloud.Organization
			want string
			gap  bool
		}{
			{"display name", &jumpcloud.Organization{ID: "org-1", DisplayName: "Acme"}, "Acme", false},
			{"no display name", &jumpcloud.Organization{ID: "org-1"}, "", false},
			{"no organization listed", nil, "", true},
		} {
			t.Run(string(level)+"/"+tc.name, func(t *testing.T) {
				mock := &mockClient{
					users: []jumpcloud.SystemUser{{ID: "u1", Email: "pat@acme.example", State: "ACTIVATED", Organization: "org-1"}},
					org:   tc.org,
				}
				rec := &componentsdk.Recorder{}
				posture, err := New(Config{Recorder: rec}, mock).Collect(context.Background(), level)
				if err != nil {
					t.Fatalf("Collect: %v", err)
				}
				want, gap := "", false
				if audit {
					want, gap = tc.want, tc.gap
				}
				if posture.OrgName != want {
					t.Errorf("org_name = %q, want %q", posture.OrgName, want)
				}
				if g, ok := gapAt(rec, detailedPath, "/org_name"); ok != gap || ok && g.Code != componentsdk.CodeInvalidResponse {
					t.Errorf("gap at /org_name = %+v, %v; want invalid_response only at audit when no organization is listed", g, ok)
				}
			})
		}
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
	if p := posture.Authentication.MFACoveragePct; p == nil || *p != 100 {
		t.Errorf("mfa_coverage_pct = %v, want 100", p)
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

	rec := &componentsdk.Recorder{}
	c := New(Config{Recorder: rec}, mock)
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
	for _, pointer := range []string{"/users", "/authentication", "/apps"} {
		if g, ok := gapAt(rec, detailedPath, pointer); !ok || g.Status != componentsdk.GapPartial || g.Code != componentsdk.CodeInvalidResponse {
			t.Errorf("gap at %s = %+v, want a partial invalid_response gap", pointer, g)
		}
	}
	idp := posture.ToIDPPosture()
	if idp.UserSecurity != nil || idp.Lifecycle != nil || idp.AppSecurity != nil {
		t.Errorf("sections from lists read in part should be left out: %+v", idp)
	}
	if idp.PrivilegedAccess == nil {
		t.Error("privileged_access comes from the administrators, which were read in full")
	}
}

// repeatedRowMock lists s1 twice and s2 once, with JumpCloud reporting total
// systems.
func repeatedRowMock(total int) *mockClient {
	mac := func(id, lastContact string) jumpcloud.System {
		return jumpcloud.System{ID: id, OS: "Mac OS X", OSFamily: "darwin", Active: true, LastContact: lastContact,
			MDM: &jumpcloud.SystemMDM{Vendor: "internal", Internal: &jumpcloud.MDMInternal{DeviceID: "mdm-" + id}}}
	}
	return &mockClient{
		users: []jumpcloud.SystemUser{{ID: "u1", State: "ACTIVATED"}},
		org:   &jumpcloud.Organization{ID: "org-1"},
		systems: []jumpcloud.System{
			mac("s1", "2026-10-01T10:00:00Z"),
			mac("s1", "2026-10-01T11:00:00Z"),
			mac("s2", "2026-10-01T10:00:00Z"),
		},
		sysTotal: total,
	}
}

func TestCollect_RepeatedSystemRowCountsOnce(t *testing.T) {
	posture, err := New(Config{Now: func() time.Time { return testNow }}, repeatedRowMock(2)).Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	d := posture.Devices
	if d.TotalSystems != 2 || d.ActiveSystems != 2 || d.MDMEnrolled != 2 || d.OSBreakdown["macOS"] != 2 || d.Partial {
		t.Errorf("devices = %+v, want 2 active MDM-enrolled Macs and not partial", d)
	}
}

func TestCollect_RepeatedSystemRowDoesNotHideAMissingSystem(t *testing.T) {
	rec := &componentsdk.Recorder{}
	posture, err := New(Config{Recorder: rec, Now: func() time.Time { return testNow }}, repeatedRowMock(3)).Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if d := posture.Devices; !d.Partial || d.TotalSystems != 2 {
		t.Errorf("devices = %+v, want 2 systems and partial", d)
	}
	for _, pointer := range []string{"/devices", "/device_inventory/per_device"} {
		g, ok := gapAt(rec, detailedPath, pointer)
		if !ok || g.Status != componentsdk.GapPartial || g.Code != componentsdk.CodeInvalidResponse || g.Unmeasured != 1 {
			t.Errorf("gap at %s = %+v, want a partial invalid_response gap with 1 unmeasured", pointer, g)
		}
	}
}

func TestToIDPPosture_Complete(t *testing.T) {
	c := New(Config{}, richMock())
	posture, err := c.Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	idp := posture.ToIDPPosture()
	if idp == nil {
		t.Fatal("should not be nil for complete data")
	}
	if idp.Provider != "jumpcloud" || idp.OrgDomain != "org-1" {
		t.Errorf("provider = %q, org_domain = %q", idp.Provider, idp.OrgDomain)
	}
	if idp.AppSecurity == nil || *idp.AppSecurity.SSOCoveragePct.Value != 66 {
		t.Errorf("app_security = %+v, want sso_coverage_pct 66, rounded down", idp.AppSecurity)
	}
	if idp.PrivilegedAccess == nil {
		t.Fatal("privileged_access should be present")
	}
	if *idp.PrivilegedAccess.SuperAdminCount != 1 {
		t.Errorf("super_admin_count = %d, want 1", *idp.PrivilegedAccess.SuperAdminCount)
	}
	us := idp.UserSecurity
	// Three users can sign in. Two have MFA, one has WebAuthn, one is locked.
	if *us.UserCount != 3 || *us.MFAUserCount != 2 || *us.PhishingResistantUserCount != 1 || *us.LockedOutUserCount != 1 {
		t.Errorf("user_security counts = %+v", us)
	}
	if *us.MFACoveragePct.Value != 66 || *us.LockedOutPct.Value != 34 {
		t.Errorf("mfa_coverage_pct = %v, locked_out_pct = %v, want 66 and 34", *us.MFACoveragePct.Value, *us.LockedOutPct.Value)
	}
	if *idp.Lifecycle.AccountCount != 4 || *idp.Lifecycle.SuspendedPct.Value != 25 {
		t.Errorf("lifecycle = %+v", idp.Lifecycle)
	}
}

func TestToIDPPosture_TrustLeavesOutCounts(t *testing.T) {
	posture, err := New(Config{}, richMock()).Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	idp := posture.ToIDPPosture()
	if idp.UserSecurity.UserCount != nil || idp.PrivilegedAccess.PrivilegedUsersCount != nil || idp.Lifecycle.AccountCount != nil {
		t.Error("counts are audit-level fields")
	}
	if !*idp.UserSecurity.UsersPresent || !*idp.PrivilegedAccess.PrivilegedUsersPresent {
		t.Error("present flags are written at every level")
	}
}

func TestAdminMFA_RequirementIsNotEnrollment(t *testing.T) {
	m := richMock()
	m.admins = []jumpcloud.Administrator{
		{ID: "a1", EnableMultiFactor: true, TOTPEnrolled: false, RoleName: "Administrator With Billing"},
		{ID: "a2", EnableMultiFactor: false, TOTPEnrolled: true, RoleName: "Administrator"},
	}
	rec := &componentsdk.Recorder{}
	posture, err := New(Config{Recorder: rec}, m).Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	a := posture.Admins
	if a.TOTPEnrolledCount != 1 || *a.TOTPEnrolledPct != 50 || a.MFARequiredCount != 1 {
		t.Errorf("admins = %+v, want 1 enrolled (50%%) and 1 required", a)
	}
	if pa := posture.ToIDPPosture().PrivilegedAccess; pa.PrivilegedMFACoveragePct.Read {
		t.Errorf("coverage is unknown while an admin lacks observable enrollment, got %v", pa.PrivilegedMFACoveragePct.Value)
	}
	if g, ok := gapAt(rec, idpPosturePath, "/privileged_access/privileged_mfa_coverage_pct"); !ok || g.Code != componentsdk.CodeUnsupported {
		t.Errorf("gap = %+v, want unsupported", g)
	}

	m.admins[0].TOTPEnrolled = true
	posture, _ = New(Config{}, m).Collect(context.Background(), componentsdk.LevelTrust)
	if pa := posture.ToIDPPosture().PrivilegedAccess; pa.PrivilegedMFACoveragePct.Value == nil || *pa.PrivilegedMFACoveragePct.Value != 100 {
		t.Error("every admin enrolled should report 100% coverage")
	}
}

func TestAdmins_SuspendedAdminIsNotCounted(t *testing.T) {
	m := richMock()
	m.admins = []jumpcloud.Administrator{
		{ID: "a1", EnableMultiFactor: true, TOTPEnrolled: true, RoleName: "Administrator With Billing"},
		{ID: "a2", EnableMultiFactor: true, TOTPEnrolled: false, RoleName: "Administrator With Billing", Suspended: true},
	}
	rec := &componentsdk.Recorder{}
	posture, err := New(Config{Recorder: rec}, m).Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	a := posture.Admins
	if a.TotalAdmins != 1 || a.SuperAdminCount == nil || *a.SuperAdminCount != 1 || a.TOTPEnrolledCount != 1 || *a.TOTPEnrolledPct != 100 || a.MFARequiredCount != 1 {
		t.Errorf("admins = %+v, want only the admin who is not suspended", a)
	}
	pa := posture.ToIDPPosture().PrivilegedAccess
	if *pa.PrivilegedUsersCount != 1 || *pa.SuperAdminCount != 1 || pa.PrivilegedMFAUserCount == nil || *pa.PrivilegedMFAUserCount != 1 {
		t.Errorf("privileged_access = %+v, want 1 privileged user, 1 super admin, and 1 with MFA", pa)
	}
	if v := pa.PrivilegedMFACoveragePct.Value; v == nil || *v != 100 {
		t.Errorf("privileged_mfa_coverage_pct = %v, want 100", v)
	}
	if g, ok := gapAt(rec, idpPosturePath, "/privileged_access/privileged_mfa_coverage_pct"); ok {
		t.Errorf("gap = %+v, want none", g)
	}
}

func TestToIDPPosture_NoEnforcementClaims(t *testing.T) {
	posture, err := New(Config{}, richMock()).Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	data, _ := json.Marshal(posture.ToIDPPosture())
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
	m := &mockClient{org: &jumpcloud.Organization{ID: "org-1"}}
	posture, err := New(Config{}, m).Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	us := posture.ToIDPPosture().UserSecurity
	if *us.UsersPresent || *us.UserCount != 0 || us.MFACoveragePct.Value != nil || !us.MFACoveragePct.Read {
		t.Errorf("user_security = %+v, want no users and null percentages", us)
	}
	if posture.Authentication.MFACoveragePct != nil {
		t.Error("the detailed MFA percentage over no users is null")
	}
}

func TestToIDPPosture_NoOrganizationIsNil(t *testing.T) {
	if (&OrgPosture{}).ToIDPPosture() != nil {
		t.Error("an artifact without org_domain should not be built")
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

// Every administrator role is privileged but Read Only, which can only
// read, and Billing Only, which can only manage billing.
func TestIsPrivileged(t *testing.T) {
	for role, want := range map[string]bool{
		"Administrator With Billing":  true,
		"Administrator":               true,
		"Manager":                     true,
		"Command Runner":              true,
		"Command Runner With Billing": true,
		"Help Desk":                   true,
		"Read Only":                   false,
		"Billing Only":                false,
	} {
		if got := isPrivileged(role); got != want {
			t.Errorf("isPrivileged(%q) = %v, want %v", role, got, want)
		}
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

// Each value JumpCloud reports in a call the collector does not make has a
// not_read gap. Each value JumpCloud does not report has an unsupported
// gap. The audit-level count gets no gap below the audit level.
func TestCollect_UnreadValueCodes(t *testing.T) {
	m := endpointMock()
	want := map[[2]string]componentsdk.Code{
		{idpPosturePath, "/user_security/inactive_pct"}:                        componentsdk.CodeNotRead,
		{idpPosturePath, "/app_security/authorized_third_party_apps_count"}:    componentsdk.CodeNotRead,
		{idpPosturePath, "/app_security/provisioning_enabled_pct"}:             componentsdk.CodeUnsupported,
		{idpPosturePath, "/privileged_access/standing_privileged_users_count"}: componentsdk.CodeUnsupported,
		{idpPosturePath, "/lifecycle/archived_pct"}:                            componentsdk.CodeUnsupported,
		{idpPosturePath, "/policy/mfa_required"}:                               componentsdk.CodeNotRead,
		{idpPosturePath, "/policy/mfa_required_user_count"}:                    componentsdk.CodeNotRead,
		{idpPosturePath, "/policy/mfa_required_coverage_pct"}:                  componentsdk.CodeNotRead,
		{idpPosturePath, "/policy/legacy_auth_blocked"}:                        componentsdk.CodeNotRead,
		{endpointPosturePath, "/hardening/screen_lock_compliant_pct"}:          componentsdk.CodeNotRead,
		{endpointPosturePath, "/compliance/compliant_pct"}:                     componentsdk.CodeNotRead,
		{endpointPosturePath, "/patching/os_supported_pct"}:                    componentsdk.CodeUnsupported,
		{endpointPosturePath, "/patching/unsupported_os_count"}:                componentsdk.CodeUnsupported,
		{endpointPosturePath, "/protection/edr_installed_pct"}:                 componentsdk.CodeUnsupported,
	}
	rec := &componentsdk.Recorder{}
	if _, err := New(Config{Recorder: rec}, m).Collect(context.Background(), componentsdk.LevelAudit); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for at, code := range want {
		if g, ok := gapAt(rec, at[0], at[1]); !ok || g.Code != code {
			t.Errorf("gap at %s %s = %+v, want %s", at[0], at[1], g, code)
		}
	}

	rec = &componentsdk.Recorder{}
	if _, err := New(Config{Recorder: rec}, m).Collect(context.Background(), componentsdk.LevelTrust); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if g, ok := gapAt(rec, endpointPosturePath, "/patching/unsupported_os_count"); ok {
		t.Errorf("a trust run has no unsupported_os_count, got gap %+v", g)
	}
	if g, ok := gapAt(rec, endpointPosturePath, "/patching/os_supported_pct"); !ok || g.Code != componentsdk.CodeUnsupported {
		t.Errorf("os_supported_pct gap = %+v, want unsupported", g)
	}
}

func TestEmailDomainTakesTheMostCommonDomain(t *testing.T) {
	cases := []struct {
		emails []string
		want   string
	}{
		{[]string{"a@Acme.example", "b@acme.example", "c@gmail.example"}, "acme.example"},
		{[]string{"a@b.example", "c@a.example"}, "a.example"},
		{[]string{"", "no-at-sign", "trailing@"}, ""},
		{nil, ""},
	}
	for _, tc := range cases {
		if got := emailDomain(tc.emails); got != tc.want {
			t.Errorf("emailDomain(%q) = %q, want %q", tc.emails, got, tc.want)
		}
	}
}
