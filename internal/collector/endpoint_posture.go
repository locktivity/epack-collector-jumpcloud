package collector

import (
	"encoding/json"

	"github.com/locktivity/epack/componentsdk"
)

// EndpointPosture is the normalized evidencepack/endpoint-posture@v1 artifact.
// Every metric is optional. An absent value has no usable reading, and the
// availability list says why. Pointers keep a known zero or false apart from
// an unknown reading. The counts, the coverage, and the device rows are
// written from the audit level, as the schema marks them.
type EndpointPosture struct {
	SchemaVersion  string                    `json:"schema_version"`
	CollectedAt    string                    `json:"collected_at"`
	Provider       string                    `json:"provider"`
	OrganizationID string                    `json:"organization_id,omitempty"`
	Scope          EndpointScope             `json:"scope"`
	Fleet          *EndpointFleet            `json:"fleet,omitempty"`
	Hardening      *EndpointHardening        `json:"hardening,omitempty"`
	Protection     *EndpointProtection       `json:"protection,omitempty"`
	MetricCoverage map[string]MetricCoverage `json:"metric_coverage,omitempty"`
	Availability   []AvailabilityEntry       `json:"availability"`

	Devices []EndpointDevice `json:"devices,omitempty"`

	// controlsByDevice holds every device's readings for the detailed
	// artifact's inventory. It is not serialized.
	controlsByDevice map[string]map[string]ControlObservation
	// coverage holds every measured control's device counts, at every
	// level, for the detailed artifact. It is not serialized.
	coverage map[string]MetricCoverage
	// unread holds, for each control, the devices whose reading could not
	// be read because a System Insights table failed or was cut short. It
	// is not serialized.
	unread map[string]unreadControl
	// noSource holds the metrics no device in the fleet has a reading
	// source for, with the code of each one's gap. It is not serialized.
	noSource map[string]componentsdk.Code
	// truncatedDevices counts the device rows left out at MaxDevices.
	truncatedDevices int
}

// unreadControl is one control's devices whose reading was not read, with
// the first error that left one out.
type unreadControl struct {
	devices map[string]error
	first   error
}

type EndpointScope struct {
	// DiscoveryComplete is nil when JumpCloud's systems list leaves it
	// unknown, as when the list ends before the total JumpCloud reported.
	DiscoveryComplete        *bool  `json:"discovery_complete"`
	ObservedDeviceCount      *int   `json:"observed_device_count,omitempty"`
	Description              string `json:"description"`
	MaxObservationAgeSeconds int64  `json:"max_observation_age_seconds"`
}

// EndpointFleet holds totals over the whole fleet. It is left out when
// discovery is incomplete, because the devices read are not the fleet.
type EndpointFleet struct {
	DevicesPresent         *bool          `json:"devices_present,omitempty"`
	DeviceCount            *int           `json:"device_count,omitempty"`
	ManagedDeviceCount     *int           `json:"managed_device_count,omitempty"`
	MDMEnrolledDeviceCount *int           `json:"mdm_enrolled_device_count,omitempty"`
	MDMEnrolledPct         Percentage     `json:"mdm_enrolled_pct,omitzero"`
	DevicesByOS            map[string]int `json:"devices_by_os,omitempty"`
}

type EndpointHardening struct {
	DiskEncryptionPct  Percentage `json:"disk_encryption_pct,omitzero"`
	FirewallEnabledPct Percentage `json:"firewall_enabled_pct,omitzero"`
}

type EndpointProtection struct {
	AntimalwareInstalledPct Percentage `json:"antimalware_installed_pct,omitzero"`
	AntimalwareHealthyPct   Percentage `json:"antimalware_healthy_pct,omitzero"`
}

// MetricCoverage partitions the in-scope fleet for one metric. The emitted
// percentage is passing / (passing + failing). Unknown devices are never
// folded into either side.
type MetricCoverage struct {
	PassingDevicesCount       int `json:"passing_device_count"`
	FailingDevicesCount       int `json:"failing_device_count"`
	UnknownDevicesCount       int `json:"unknown_device_count"`
	NotApplicableDevicesCount int `json:"not_applicable_device_count"`
}

type AvailabilityEntry struct {
	Path    string `json:"path"`
	Reason  string `json:"reason"`
	Message string `json:"message,omitempty"`
}

const (
	reasonUnsupported      = "unsupported"
	reasonPermissionDenied = "permission_denied"
	reasonNotRead          = "not_read"
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

// Percentage is a normalized percentage. It is left out when Read is false.
// Otherwise it is written as Value, which is nil over an empty population.
type Percentage struct {
	Value *float64
	Read  bool
}

// IsZero reports whether the percentage was not read, for omitzero.
func (p Percentage) IsZero() bool { return !p.Read }

// MarshalJSON writes the value, or null.
func (p Percentage) MarshalJSON() ([]byte, error) { return json.Marshal(p.Value) }

// known returns a read percentage of v.
func known(v *int) Percentage {
	if v == nil {
		return Percentage{Read: true}
	}
	f := float64(*v)
	return Percentage{Value: &f, Read: true}
}
