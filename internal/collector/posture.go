package collector

const SchemaVersion = "1.0.0"

// OrgPosture is the top-level output of the JumpCloud collector.
type OrgPosture struct {
	SchemaVersion    string `json:"schema_version"`
	CollectedAt      string `json:"collected_at"`
	CollectedAtLevel string `json:"collected_at_level"`
	OrgID            string `json:"org_id,omitempty"`

	// Trust level: aggregate metrics (always present after successful user fetch)
	Users          UserMetrics           `json:"users"`
	Authentication AuthenticationMetrics `json:"authentication"`
	Admins         *AdminMetrics         `json:"admins,omitempty"`
	Apps           *AppMetrics           `json:"apps,omitempty"`
	Policies       *PolicyMetrics        `json:"policies,omitempty"`
	Devices        *DeviceMetrics        `json:"devices,omitempty"`

	// Audit level: per-entity inventories
	UserInventory   *UserInventory   `json:"user_inventory,omitempty"`
	AppInventory    *AppInventory    `json:"app_inventory,omitempty"`
	GroupInventory  *GroupInventory  `json:"group_inventory,omitempty"`
	DeviceInventory *DeviceInventory `json:"device_inventory,omitempty"`
	PolicyInventory *PolicyInventory `json:"policy_inventory,omitempty"`

	// Internal level: audit events
	AuditLog *AuditLog `json:"audit_log,omitempty"`

	Diagnostics *Diagnostics `json:"diagnostics,omitempty"`

	endpoint *EndpointPosture
}

// ToEndpointPosture returns the normalized endpoint-posture@v1 artifact, or
// nil when device discovery failed and there is no device evidence at all.
func (o *OrgPosture) ToEndpointPosture() *EndpointPosture {
	return o.endpoint
}

// --- Trust-level metrics ---

// UserMetrics contains aggregate user counts.
type UserMetrics struct {
	Total     int  `json:"total"`
	Active    int  `json:"active"`
	Staged    int  `json:"staged"`
	Suspended int  `json:"suspended"`
	Locked    int  `json:"locked"`
	Partial   bool `json:"partial,omitempty"`
}

// AuthenticationMetrics contains MFA adoption metrics.
type AuthenticationMetrics struct {
	MFACoveragePct         float64 `json:"mfa_coverage_pct"`
	TOTPEnrolledPct        float64 `json:"totp_enrolled_pct"`
	WebAuthnEnrolledPct    float64 `json:"webauthn_enrolled_pct"`
	PushEnrolledPct        float64 `json:"push_enrolled_pct"`
	MFANotEnrolledCount    int     `json:"mfa_not_enrolled_count"`
	PortalMFARequiredCount int     `json:"portal_mfa_required_count"`
}

// AdminMetrics contains privileged user counts.
type AdminMetrics struct {
	TotalAdmins         int     `json:"total_admins"`
	SuperAdminCount     int     `json:"super_admin_count"`
	AdminMFACoveragePct float64 `json:"admin_mfa_coverage_pct"`
	Partial             bool    `json:"partial,omitempty"`
}

// AppMetrics contains SSO application metrics.
type AppMetrics struct {
	TotalApps      int     `json:"total_apps"`
	SSOEnabledApps int     `json:"sso_enabled_apps"`
	SSOCoveragePct float64 `json:"sso_coverage_pct"`
	Partial        bool    `json:"partial,omitempty"`
}

// PolicyMetrics contains authentication policy summary.
// These describe policy configuration, not effective enforcement.
type PolicyMetrics struct {
	TotalPolicies                   int  `json:"total_policies"`
	MFARequiredPolicies             int  `json:"mfa_required_policies"`
	HasMFARequiredPolicy            bool `json:"has_mfa_required_policy"`
	HasDeviceManagedCondition       bool `json:"has_device_managed_condition"`
	HasPhishingResistantAdminPolicy bool `json:"has_phishing_resistant_admin_policy"`
}

// DeviceMetrics contains managed device counts.
type DeviceMetrics struct {
	TotalSystems  int            `json:"total_systems"`
	ActiveSystems int            `json:"active_systems"`
	MDMEnrolled   int            `json:"mdm_enrolled"`
	OSBreakdown   map[string]int `json:"os_breakdown"`
	Partial       bool           `json:"partial,omitempty"`
}

// --- Audit-level inventories ---

// UserInventory contains per-user detail.
type UserInventory struct {
	PerUser          []UserRow `json:"per_user"`
	Truncated        bool      `json:"truncated,omitempty"`
	TruncatedDropped int       `json:"truncated_dropped,omitempty"`
}

// UserRow describes one user in the inventory.
type UserRow struct {
	Username        string `json:"username"`
	Email           string `json:"email"`
	State           string `json:"state"`
	MFAEnrolled     bool   `json:"mfa_enrolled"`
	TOTPEnabled     bool   `json:"totp_enabled"`
	WebAuthnEnabled bool   `json:"webauthn_enabled"`
	AccountLocked   bool   `json:"account_locked"`
	Created         string `json:"created,omitempty"`
}

// AppInventory contains per-application detail.
type AppInventory struct {
	PerApp []AppRow `json:"per_app"`
}

// AppRow describes one application.
type AppRow struct {
	Name       string `json:"name"`
	SSOType    string `json:"sso_type,omitempty"`
	SSOEnabled bool   `json:"sso_enabled"`
}

// GroupInventory contains user and system group summaries.
type GroupInventory struct {
	UserGroups   []GroupRow `json:"user_groups"`
	SystemGroups []GroupRow `json:"system_groups"`
}

// GroupRow describes one group.
type GroupRow struct {
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
}

// DeviceInventory contains per-system detail.
type DeviceInventory struct {
	PerDevice        []DeviceRow `json:"per_device"`
	Truncated        bool        `json:"truncated,omitempty"`
	TruncatedDropped int         `json:"truncated_dropped,omitempty"`
}

// DeviceRow describes one managed system.
type DeviceRow struct {
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	OSVersion    string `json:"os_version,omitempty"`
	Active       bool   `json:"active"`
	AgentVersion string `json:"agent_version,omitempty"`
	MDMEnrolled  bool   `json:"mdm_enrolled"`
}

// PolicyInventory contains per-policy detail.
type PolicyInventory struct {
	AuthPolicies []AuthPolicyRow `json:"auth_policies"`
}

// AuthPolicyRow describes one authentication policy.
type AuthPolicyRow struct {
	Name           string   `json:"name"`
	Type           string   `json:"type"`
	Disabled       bool     `json:"disabled"`
	MFARequired    bool     `json:"mfa_required"`
	AllowedFactors []string `json:"allowed_factors,omitempty"`
	DeviceManaged  bool     `json:"device_managed"`
}

// --- Internal-level data ---

// AuditLog holds a window of Directory Insights events.
type AuditLog struct {
	WindowDays       int             `json:"window_days"`
	CountByType      map[string]int  `json:"count_by_type"`
	Events           []AuditEventRow `json:"events,omitempty"`
	Truncated        bool            `json:"truncated,omitempty"`
	TruncatedDropped int             `json:"truncated_dropped,omitempty"`
}

// AuditEventRow describes one audit event.
type AuditEventRow struct {
	EventType string `json:"event_type"`
	Timestamp string `json:"timestamp"`
	Actor     string `json:"actor,omitempty"`
}
