package collector

import (
	"net/http"
	"testing"

	"github.com/locktivity/epack-collector-jumpcloud/internal/jumpcloud"
	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

// kitOperations are every call the collector can make.
var kitOperations = []string{
	jumpcloud.OpListSystemUsers,
	jumpcloud.OpListOrganizations,
	jumpcloud.OpListApplications,
	jumpcloud.OpListAdministrators,
	jumpcloud.OpListAuthPolicies,
	jumpcloud.OpListSystems,
	jumpcloud.OpListBitLocker,
	jumpcloud.OpListWindowsSecurityCenter,
	jumpcloud.OpListWindowsSecurityProducts,
	jumpcloud.OpListALF,
	jumpcloud.OpListInsightUsers,
	jumpcloud.OpListUserGroups,
	jumpcloud.OpListSystemGroups,
	jumpcloud.OpQueryEvents,
}

// kitIgnore keeps the text lists readers parse out of the value comparison.
// A fault adds a diagnostics warning and an availability entry by design,
// and the gaps say the same.
var kitIgnore = map[string][]string{
	detailedPath:        {"/diagnostics"},
	endpointPosturePath: {"/availability"},
}

// kitClean is the clean organization, with the values a fixed collector
// reports for it pinned.
func kitClean() collectortest.Scenario {
	return collectortest.Scenario{
		Name:      "clean",
		Responses: kitCleanTenant().responses(),
		Expect: map[string]map[string]any{
			detailedPath: {
				"/org_id":                                       kitOrgID,
				"/users/total":                                  5,
				"/authentication/mfa_coverage_pct":              66.67,
				"/admins/totp_enrolled_pct":                     100,
				"/apps/sso_coverage_pct":                        66.67,
				"/policies/has_phishing_resistant_admin_policy": true,
				"/policies/has_device_managed_condition":        true,
				"/device_controls/disk_encryption/passing_pct":  66.67,
				"/device_controls/firewall/passing_pct":         100,
				"/audit_log/count_by_type/user_update":          2,
			},
			idpPosturePath: {
				"/org_domain":                                    kitOrgID,
				"/user_security/user_count":                      3,
				"/user_security/mfa_coverage_pct":                66,
				"/user_security/locked_out_pct":                  34,
				"/app_security/sso_coverage_pct":                 66,
				"/privileged_access/privileged_mfa_coverage_pct": 100,
				"/lifecycle/suspended_pct":                       20,
			},
			endpointPosturePath: {
				"/organization_id":                           kitOrgID,
				"/fleet/device_count":                        3,
				"/fleet/mdm_enrolled_pct":                    66,
				"/hardening/disk_encryption_pct":             66,
				"/protection/antimalware_healthy_pct":        100,
				"/devices/1/local_admin_accounts/0/username": "alice",
			},
		},
	}
}

func TestCollectorKit(t *testing.T) {
	clean := kitCleanTenant()
	collectortest.Run(t, collectortest.Suite{
		Spec:    Spec("test", "collectortest"),
		Run:     Run,
		Config:  kitConfig(),
		Secrets: kitSecrets(),
		Clock:   kitNow,
		Scenarios: []collectortest.Scenario{
			kitClean(),
			{
				Name:          "API key rejected",
				ExpectFailure: componentsdk.CodeAuthFailed,
				Responses: []collectortest.Response{{
					URL: kitConsole + "/api/systemusers", Status: http.StatusUnauthorized, Body: `{"message":"Unauthorized"}`,
				}},
			},
			{
				Name:      "empty organization",
				Responses: kitEmptyTenant().responses(),
				Expect: map[string]map[string]any{
					detailedPath: {
						"/users/total":                                 0,
						"/authentication/mfa_coverage_pct":             nil,
						"/admins/totp_enrolled_pct":                    nil,
						"/apps/sso_coverage_pct":                       nil,
						"/device_controls/disk_encryption/passing_pct": nil,
					},
					idpPosturePath: {
						"/user_security/users_present":                false,
						"/user_security/mfa_coverage_pct":             nil,
						"/lifecycle/accounts_present":                 false,
						"/privileged_access/privileged_users_present": false,
					},
					endpointPosturePath: {
						"/fleet/devices_present":         false,
						"/fleet/device_count":            0,
						"/hardening/disk_encryption_pct": nil,
						"/devices":                       collectortest.Absent,
					},
				},
			},
			{
				Name:          "configured organization not listed",
				Config:        map[string]any{"org_id": "org-other"},
				ExpectFailure: componentsdk.CodeConfigInvalid,
				Responses:     clean.responses(),
			},
			{
				Name:          "several organizations and no org_id",
				ExpectFailure: componentsdk.CodeConfigInvalid,
				Responses: append([]collectortest.Response{{
					URL:  kitConsole + "/api/organizations",
					Body: kitV1(2, kitOrgRow, `{"_id": "org-second", "displayName": "Second Org"}`),
				}}, clean.responses()...),
			},
			{
				// A service account cannot read /api/organizations.
				Name:      "organization list refused",
				Responses: append([]collectortest.Response{kitRefused(kitConsole + "/api/organizations")}, clean.responses()...),
				Expect: map[string]map[string]any{
					detailedPath:        {"/org_id": collectortest.Absent},
					idpPosturePath:      {"/org_domain": kitOrgID},
					endpointPosturePath: {"/organization_id": collectortest.Absent},
				},
			},
			{
				Name: "System Insights refused",
				Responses: append([]collectortest.Response{
					kitRefused(kitConsole + "/api/v2/systeminsights/bitlocker_info"),
					kitRefused(kitConsole + "/api/v2/systeminsights/windows_security_center"),
					kitRefused(kitConsole + "/api/v2/systeminsights/windows_security_products"),
					kitRefused(kitConsole + "/api/v2/systeminsights/alf"),
					kitRefused(kitConsole + "/api/v2/systeminsights/users"),
				}, clean.responses()...),
				Expect: map[string]map[string]any{
					detailedPath: {
						"/device_controls/disk_encryption":        collectortest.Absent,
						"/device_controls/firewall":               collectortest.Absent,
						"/device_inventory/per_device/1/controls": collectortest.Absent,
					},
					endpointPosturePath: {
						"/hardening":                      collectortest.Absent,
						"/protection":                     collectortest.Absent,
						"/fleet/device_count":             3,
						"/devices/0/local_admin_accounts": collectortest.Absent,
					},
				},
			},
			{
				// The collect key leaves the detailed file out, so the run
				// skips the calls only it needs.
				Name:      "detailed file not collected",
				Config:    map[string]any{"collect": []any{"idp-posture", "endpoint-posture"}},
				Responses: clean.responses(),
				Expect: map[string]map[string]any{
					idpPosturePath:      {"/user_security/mfa_coverage_pct": 66},
					endpointPosturePath: {"/hardening/disk_encryption_pct": 66},
				},
			},
			{
				// JumpCloud reports seven users and ends the list after five.
				Name: "users listed in part",
				Responses: append([]collectortest.Response{{
					URL: kitConsole + "/api/systemusers", Body: kitV1(7, kitUserRows...),
				}}, clean.responses()...),
				Expect: map[string]map[string]any{
					detailedPath:   {"/users/partial": true, "/users/total": 5},
					idpPosturePath: {"/user_security": collectortest.Absent, "/lifecycle": collectortest.Absent, "/app_security/app_count": 3},
				},
			},
			{
				// JumpCloud reports four systems and ends the list after
				// three, so whether every device was listed is unknown.
				Name: "systems listed in part",
				Responses: append([]collectortest.Response{{
					URL: kitConsole + "/api/systems", Body: kitV1(4, kitSystemRows...),
				}}, clean.responses()...),
				Expect: map[string]map[string]any{
					detailedPath: {
						"/device_controls/discovery_complete": nil,
						"/device_controls/disk_encryption":    collectortest.Absent,
						"/devices/partial":                    true,
					},
					endpointPosturePath: {
						"/scope/discovery_complete":    nil,
						"/scope/observed_device_count": 3,
						"/fleet":                       collectortest.Absent,
						"/hardening":                   collectortest.Absent,
						"/devices/0/hostname":          "lin-01",
					},
				},
			},
		},
		// The users list is the sign-in. The organization list fails the run
		// when the configured org_id does not resolve.
		Required:      []string{jumpcloud.OpListSystemUsers, jumpcloud.OpListOrganizations},
		Ignore:        kitIgnore,
		Operations:    kitOperations,
		GapOperations: true,
	})
}

func TestRunRejectsInvalidConfiguration(t *testing.T) {
	cases := map[string]struct {
		config  map[string]any
		secrets map[string]string
	}{
		"org_id not a string":          {map[string]any{"org_id": 42}, kitSecrets()},
		"observation age not whole":    {map[string]any{"max_observation_age_hours": 1.5}, kitSecrets()},
		"observation age out of range": {map[string]any{"max_observation_age_hours": 9000}, kitSecrets()},
		"no API key":                   {kitConfig(), nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			res := componentsdk.RunInProcess(Spec("test", "collectortest"), Run, componentsdk.InProcessOptions{
				Config:  tc.config,
				Secrets: tc.secrets,
			})
			if res.ExitCode != 2 || res.Failure == nil || res.Failure.Code != componentsdk.CodeConfigInvalid {
				t.Errorf("exit %d, failure %+v; want exit 2 with config_invalid", res.ExitCode, res.Failure)
			}
		})
	}
}
