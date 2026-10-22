package collector

// EndpointPosture is the normalized evidencepack/endpoint-posture@v1 artifact.
// Every metric is optional: an absent value means no usable reading, and the
// availability list explains why. Pointers keep a known zero or false
// distinguishable from an unknown reading.
type EndpointPosture struct {
	SchemaVersion  string                    `json:"schema_version"`
	CollectedAt    string                    `json:"collected_at"`
	Provider       string                    `json:"provider"`
	OrganizationID string                    `json:"organization_id,omitempty"`
	Scope          EndpointScope             `json:"scope"`
	Fleet          *EndpointFleet            `json:"fleet,omitempty"`
	Hardening      *EndpointHardening        `json:"hardening,omitempty"`
	Protection     *EndpointProtection       `json:"protection,omitempty"`
	MetricCoverage map[string]MetricCoverage `json:"metric_coverage"`
	Availability   []AvailabilityEntry       `json:"availability"`

	Devices     []EndpointDevice         `json:"devices,omitempty"`
	Inventories map[string]InventoryMeta `json:"inventories,omitempty"`

	// controlsByDevice holds every device's readings for the detailed
	// artifact's inventory; it is not serialized.
	controlsByDevice map[string]map[string]ControlObservation
}

type EndpointScope struct {
	DiscoveryComplete        bool   `json:"discovery_complete"`
	ObservedDevicesCount     int    `json:"observed_devices_count"`
	Description              string `json:"description"`
	MaxObservationAgeSeconds int64  `json:"max_observation_age_seconds"`
}

// EndpointFleet holds complete-population totals. It is omitted entirely when
// discovery is incomplete, because a fetched sample is not the fleet.
type EndpointFleet struct {
	DevicesCount            *int           `json:"devices_count,omitempty"`
	ManagedDevicesCount     *int           `json:"managed_devices_count,omitempty"`
	MDMEnrolledDevicesCount *int           `json:"mdm_enrolled_devices_count,omitempty"`
	DevicesByOS             map[string]int `json:"devices_by_os,omitempty"`
}

type EndpointHardening struct {
	DiskEncryptionPct      *float64 `json:"disk_encryption_pct,omitempty"`
	ScreenLockCompliantPct *float64 `json:"screen_lock_compliant_pct,omitempty"`
	FirewallEnabledPct     *float64 `json:"firewall_enabled_pct,omitempty"`
}

type EndpointProtection struct {
	AntimalwareInstalledPct *float64 `json:"antimalware_installed_pct,omitempty"`
	AntimalwareHealthyPct   *float64 `json:"antimalware_healthy_pct,omitempty"`
	EDRInstalledPct         *float64 `json:"edr_installed_pct,omitempty"`
	EDRHealthyPct           *float64 `json:"edr_healthy_pct,omitempty"`
}

// MetricCoverage partitions the in-scope fleet for one metric. The emitted
// percentage is passing / (passing + failing); unknown devices are never
// folded into either side.
type MetricCoverage struct {
	PassingDevicesCount       int `json:"passing_devices_count"`
	FailingDevicesCount       int `json:"failing_devices_count"`
	UnknownDevicesCount       int `json:"unknown_devices_count"`
	NotApplicableDevicesCount int `json:"not_applicable_devices_count"`
}

type AvailabilityEntry struct {
	Path    string `json:"path"`
	Reason  string `json:"reason"`
	Message string `json:"message,omitempty"`
}

const (
	reasonUnsupported      = "unsupported"
	reasonPermissionDenied = "permission_denied"
	reasonNotConfigured    = "not_configured"
	reasonStale            = "stale"
	reasonPartial          = "partial"
	reasonSourceError      = "source_error"
)

type EndpointDevice struct {
	DeviceID           string                        `json:"device_id"`
	Hostname           string                        `json:"hostname,omitempty"`
	OSFamily           string                        `json:"os_family"`
	OSName             string                        `json:"os_name,omitempty"`
	OSVersion          string                        `json:"os_version,omitempty"`
	AssignedUser       *AssignedUser                 `json:"assigned_user,omitempty"`
	ManagementState    string                        `json:"management_state"`
	InScope            bool                          `json:"in_scope"`
	CreatedAt          string                        `json:"created_at,omitempty"`
	LastSeenAt         string                        `json:"last_seen_at,omitempty"`
	Controls           map[string]ControlObservation `json:"controls"`
	LocalAdminAccounts *[]LocalAdminAccount          `json:"local_admin_accounts,omitempty"`
}

type AssignedUser struct {
	UserID string `json:"user_id"`
	Login  string `json:"login,omitempty"`
}

type ControlObservation struct {
	State      string `json:"state"`
	ObservedAt string `json:"observed_at,omitempty"`
}

const (
	statePass          = "pass"
	stateFail          = "fail"
	stateUnknown       = "unknown"
	stateNotApplicable = "not_applicable"
)

type LocalAdminAccount struct {
	AccountID string `json:"account_id,omitempty"`
	Username  string `json:"username,omitempty"`
}

// InventoryMeta describes collection and output completeness for an
// inventory array, keyed by the array's path.
type InventoryMeta struct {
	CollectionComplete bool `json:"collection_complete"`
	OutputTruncated    bool `json:"output_truncated"`
	ReturnedRowsCount  int  `json:"returned_rows_count"`
	TotalRowsCount     *int `json:"total_rows_count,omitempty"`
	DroppedRowsCount   *int `json:"dropped_rows_count,omitempty"`
}
