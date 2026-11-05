package collector

import (
	"context"
	"time"

	"github.com/locktivity/epack-collector-jumpcloud/internal/jumpcloud"
	"github.com/locktivity/epack/componentsdk"
)

// StatusFunc is called to report indeterminate status updates.
type StatusFunc func(message string)

// ProgressFunc is called to report determinate progress (current/total).
type ProgressFunc func(current, total int64, message string)

// Config holds parsed configuration for the collector.
type Config struct {
	OrgID string
	// MaxObservationAge is how old device telemetry may be and still count
	// as a current reading. Zero uses DefaultMaxObservationAge.
	MaxObservationAge time.Duration
	OnStatus          StatusFunc   `json:"-"`
	OnProgress        ProgressFunc `json:"-"`
	// Recorder records the gaps of the run. Nil records them nowhere.
	Recorder *componentsdk.Recorder `json:"-"`
	// Now returns the time of the run. Nil uses time.Now.
	Now func() time.Time `json:"-"`
	// Selected reports whether the run collects the artifact at a
	// location, as componentsdk.Selected does. Nil collects every one.
	Selected func(componentsdk.Location) bool `json:"-"`
}

// DefaultMaxObservationAge is a collection rule, not a security standard:
// it tolerates laptops that are offline over a long weekend while keeping
// month-old readings from passing as current.
const DefaultMaxObservationAge = 7 * 24 * time.Hour

func (c Config) maxObservationAge() time.Duration {
	if c.MaxObservationAge > 0 {
		return c.MaxObservationAge
	}
	return DefaultMaxObservationAge
}

// JumpCloudClient defines the API surface the collector requires.
type JumpCloudClient interface {
	ListSystemUsers(ctx context.Context) ([]jumpcloud.SystemUser, int, error)
	ListApplications(ctx context.Context) ([]jumpcloud.Application, int, error)
	GetOrganization(ctx context.Context, orgID string) (*jumpcloud.Organization, error)
	ListAdministrators(ctx context.Context) ([]jumpcloud.Administrator, int, error)
	ListSystems(ctx context.Context) ([]jumpcloud.System, int, error)
	ListUserGroups(ctx context.Context) ([]jumpcloud.UserGroup, bool, error)
	ListSystemGroups(ctx context.Context) ([]jumpcloud.SystemGroup, bool, error)
	ListAuthPolicies(ctx context.Context) ([]jumpcloud.AuthPolicy, bool, error)
	QueryEvents(ctx context.Context, service string, start, end time.Time, limit int) ([]jumpcloud.DirectoryInsightsEvent, error)
	ListBitLockerInfo(ctx context.Context) ([]jumpcloud.InsightBitLocker, bool, error)
	ListALF(ctx context.Context) ([]jumpcloud.InsightALF, bool, error)
	ListWindowsSecurityCenter(ctx context.Context) ([]jumpcloud.InsightWindowsSecurityCenter, bool, error)
	ListWindowsSecurityProducts(ctx context.Context) ([]jumpcloud.InsightWindowsSecurityProduct, bool, error)
	ListInsightUsers(ctx context.Context) ([]jumpcloud.InsightUser, bool, error)
}

// Collector gathers JumpCloud posture data.
type Collector struct {
	cfg    Config
	client JumpCloudClient
}

// New creates a Collector.
func New(cfg Config, client JumpCloudClient) *Collector {
	return &Collector{cfg: cfg, client: client}
}

func (c *Collector) now() time.Time {
	if c.cfg.Now != nil {
		return c.cfg.Now()
	}
	return time.Now()
}

// selected reports whether the run collects the artifact at path.
func (c *Collector) selected(path string) bool {
	return c.cfg.Selected == nil || c.cfg.Selected(componentsdk.Location{Path: path})
}

func (c *Collector) status(msg string) {
	if c.cfg.OnStatus != nil {
		c.cfg.OnStatus(msg)
	}
}
