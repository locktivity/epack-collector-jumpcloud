package collector

import (
	"encoding/json"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

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
				"/org_name":                                     "Example Org",
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

// kitReadOnlyAdmins adds a Read Only and a Billing Only administrator,
// neither with TOTP enrolled. Neither role can change who has access or how
// users sign in, so the privileged users are still the two administrators
// with TOTP, and their MFA coverage stays known. The policy values are left
// out with a not_read gap.
func kitReadOnlyAdmins(clean kitTenant) collectortest.Scenario {
	rows := append(slices.Clone(kitAdminRows),
		`{"_id": "a3", "email": "auditor@example.com", "enableMultiFactor": false, "totpEnrolled": false, "roleName": "Read Only", "created": "2024-07-01T00:00:00.000Z"}`,
		`{"_id": "a4", "email": "finance@example.com", "enableMultiFactor": false, "totpEnrolled": false, "roleName": "Billing Only", "created": "2024-08-01T00:00:00.000Z"}`,
	)
	t := clean
	t.admins = kitV1(len(rows), rows...)
	return collectortest.Scenario{
		Name:      "read-only and billing administrators",
		Responses: t.responses(),
		Expect: map[string]map[string]any{
			detailedPath: {"/admins/total_admins": 4},
			idpPosturePath: {
				"/privileged_access/privileged_users_count":      2,
				"/privileged_access/privileged_mfa_user_count":   2,
				"/privileged_access/privileged_mfa_coverage_pct": 100,
				"/policy": collectortest.Absent,
			},
		},
	}
}

// kitAdminWithNoRole lists the billing administrator with a null roleName.
// That administrator could hold any role, so the counts that depend on
// roles are left out, and the Administrator role still shows that a
// privileged user is present.
func kitAdminWithNoRole(clean kitTenant) collectortest.Scenario {
	t := clean
	t.admins = kitV1(len(kitAdminRows), kitFieldTo(kitAdminRows[0], "roleName", nil), kitAdminRows[1])
	return collectortest.Scenario{
		Name:      "administrator with no role",
		Responses: t.responses(),
		Expect: map[string]map[string]any{
			detailedPath: {"/admins/super_admin_count": nil, "/admins/total_admins": 2},
			idpPosturePath: {
				"/privileged_access/super_admin_count":        collectortest.Absent,
				"/privileged_access/privileged_users_count":   collectortest.Absent,
				"/privileged_access/privileged_users_present": true,
			},
		},
	}
}

// kitSystemsWithNoLastContact lists every system with a null lastContact,
// which leaves the agent's fde.active flag undated. The Mac and the server
// count as unknown, and the disk encryption percentage is left out rather
// than taken over the PC alone.
func kitSystemsWithNoLastContact(clean kitTenant) collectortest.Scenario {
	t := clean
	t.systems = kitFieldTo(clean.systems, "lastContact", nil)
	return collectortest.Scenario{
		Name:      "systems with no lastContact",
		Responses: t.responses(),
		Expect: map[string]map[string]any{
			detailedPath: {
				"/device_controls/disk_encryption/passing_pct":           nil,
				"/device_controls/disk_encryption/unknown_devices_count": 2,
			},
			endpointPosturePath: {
				"/hardening/disk_encryption_pct":                                      collectortest.Absent,
				"/metric_coverage/hardening.disk_encryption_pct/unknown_device_count": 2,
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
					detailedPath:        {"/org_id": collectortest.Absent, "/org_name": collectortest.Absent},
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
			kitReadOnlyAdmins(clean),
			kitAdminWithNoRole(clean),
			kitSystemsWithNoLastContact(clean),
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

// kitRun runs the collector against the responses with the config, and
// fails the test when the run fails.
func kitRun(t *testing.T, config map[string]any, responses []collectortest.Response) componentsdk.InProcessResult {
	t.Helper()
	replay, err := collectortest.NewReplay(collectortest.Scenario{Name: t.Name(), Responses: responses})
	if err != nil {
		t.Fatal(err)
	}
	res := componentsdk.RunInProcess(Spec("test", "collectortest"), Run, componentsdk.InProcessOptions{
		Config:    config,
		Secrets:   kitSecrets(),
		Transport: replay,
		Clock:     func() time.Time { return kitNow },
	})
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	return res
}

// kitField returns the top-level key of the artifact the run wrote at path.
func kitField(t *testing.T, res componentsdk.InProcessResult, path, key string) any {
	t.Helper()
	v, _ := kitAt(t, res, path, "/"+key)
	return v
}

// kitAt returns the value at pointer in the artifact the run wrote at path,
// and whether the artifact has one. The pointer names object keys only.
func kitAt(t *testing.T, res componentsdk.InProcessResult, path, pointer string) (any, bool) {
	t.Helper()
	for _, artifact := range res.Artifacts {
		if artifact.Path != path {
			continue
		}
		var v any
		if err := json.Unmarshal(artifact.Data, &v); err != nil {
			t.Fatal(err)
		}
		for _, key := range strings.Split(pointer, "/")[1:] {
			obj, ok := v.(map[string]any)
			if !ok {
				return nil, false
			}
			if v, ok = obj[key]; !ok {
				return nil, false
			}
		}
		return v, true
	}
	t.Fatalf("the run wrote no %s", path)
	return nil, false
}

// kitGap returns the gap the run recorded at path and pointer.
func kitGap(res componentsdk.InProcessResult, path, pointer string) (componentsdk.Gap, bool) {
	for _, g := range res.Result.Gaps {
		if g.Path == path && g.Pointer == pointer {
			return g, true
		}
	}
	return componentsdk.Gap{}, false
}

// kitWantPartial reports a problem unless the run left the value at path
// and pointer out with an invalid_response partial gap over unmeasured
// items. absent says whether the value is left out of the artifact, rather
// than written as null.
func kitWantPartial(t *testing.T, res componentsdk.InProcessResult, path, pointer string, absent bool, unmeasured int) {
	t.Helper()
	switch v, ok := kitAt(t, res, path, pointer); {
	case absent && ok:
		t.Errorf("%s %s = %v, want it left out", path, pointer, v)
	case !absent && (!ok || v != nil):
		t.Errorf("%s %s = %v, want null", path, pointer, v)
	}
	g, ok := kitGap(res, path, pointer)
	if !ok || g.Status != componentsdk.GapPartial || g.Code != componentsdk.CodeInvalidResponse || g.Unmeasured != unmeasured {
		t.Errorf("gap at %s %s = %+v, want a partial invalid_response gap over %d", path, pointer, g, unmeasured)
	}
}

// An administrator JumpCloud lists with no roleName could hold any role,
// Administrator With Billing included. So super_admin_count, and each
// identity value that depends on roles, is left out with a partial gap
// rather than written lower. Another administrator's privileged role still
// shows that one is present.
func TestRunLeavesRoleCountsOutForAnAdministratorWithNoRole(t *testing.T) {
	roleDependent := []string{
		"/privileged_access/super_admin_count",
		"/privileged_access/privileged_users_count",
		"/privileged_access/privileged_mfa_user_count",
		"/privileged_access/privileged_mfa_coverage_pct",
	}
	for name, role := range map[string]any{"missing": kitDropped{}, "null": nil, "empty": ""} {
		t.Run(name, func(t *testing.T) {
			tenant := kitCleanTenant()
			tenant.admins = kitV1(2, kitFieldTo(kitAdminRows[0], "roleName", role), kitAdminRows[1])
			res := kitRun(t, kitConfig(), tenant.responses())

			kitWantPartial(t, res, detailedPath, "/admins/super_admin_count", false, 1)
			if v, _ := kitAt(t, res, detailedPath, "/admins/total_admins"); v != float64(2) {
				t.Errorf("total_admins = %v, want 2", v)
			}
			for _, pointer := range roleDependent {
				kitWantPartial(t, res, idpPosturePath, pointer, true, 1)
			}
			if v, _ := kitAt(t, res, idpPosturePath, "/privileged_access/privileged_users_present"); v != true {
				t.Errorf("privileged_users_present = %v, want true from the Administrator role", v)
			}
			if g, ok := kitGap(res, idpPosturePath, "/privileged_access/privileged_users_present"); ok {
				t.Errorf("gap at privileged_users_present = %+v, want none", g)
			}
			for _, check := range res.Result.Checks {
				t.Errorf("check finding %+v", check)
			}
		})
	}

	t.Run("no role known", func(t *testing.T) {
		tenant := kitCleanTenant()
		tenant.admins = kitFieldTo(tenant.admins, "roleName", nil)
		res := kitRun(t, kitConfig(), tenant.responses())
		kitWantPartial(t, res, detailedPath, "/admins/super_admin_count", false, 2)
		for _, pointer := range append(roleDependent, "/privileged_access/privileged_users_present") {
			kitWantPartial(t, res, idpPosturePath, pointer, true, 2)
		}
	})
}

// When JumpCloud leaves out a field a device's reading needs, the device
// counts as unknown, and the control's percentage is left out with a
// partial gap over those devices, in both artifacts. An unknown that
// JumpCloud's data gives, such as a stale reading or an unrecognized
// state, leaves the percentage over the other devices with no gap.
func TestRunLeavesOutAPercentageWhenAFieldIsMissing(t *testing.T) {
	disk, firewall, installed, healthy := measuredMetrics[0], measuredMetrics[1], measuredMetrics[2], measuredMetrics[3]
	type metric struct {
		endpointMetric
		unmeasured, unknown int
	}
	cases := []struct {
		name    string
		edit    func(*kitTenant)
		metrics []metric
	}{
		{"systems lastContact null", func(k *kitTenant) { k.systems = kitFieldTo(k.systems, "lastContact", nil) },
			[]metric{{disk, 2, 2}}},
		{"systems fde.active dropped", func(k *kitTenant) { k.systems = kitFieldTo(k.systems, "fde/active", kitDropped{}) },
			[]metric{{disk, 2, 2}}},
		{"systems fde dropped", func(k *kitTenant) { k.systems = kitFieldTo(k.systems, "fde", kitDropped{}) },
			[]metric{{disk, 2, 2}}},
		{"systems fde null", func(k *kitTenant) { k.systems = kitFieldTo(k.systems, "fde", nil) },
			[]metric{{disk, 2, 2}}},
		{"bitlocker_info collection_time null", func(k *kitTenant) { k.bitlocker = kitFieldTo(k.bitlocker, "collection_time", nil) },
			[]metric{{disk, 1, 1}}},
		{"bitlocker_info system_id null", func(k *kitTenant) { k.bitlocker = kitFieldTo(k.bitlocker, "system_id", nil) },
			[]metric{{disk, 1, 1}}},
		{"bitlocker_info protection_status null", func(k *kitTenant) { k.bitlocker = kitFieldTo(k.bitlocker, "protection_status", nil) },
			[]metric{{disk, 1, 1}}},
		{"bitlocker_info conversion_status dropped", func(k *kitTenant) { k.bitlocker = kitFieldTo(k.bitlocker, "conversion_status", kitDropped{}) },
			[]metric{{disk, 1, 1}}},
		{"alf collection_time null", func(k *kitTenant) { k.alf = kitFieldTo(k.alf, "collection_time", nil) },
			[]metric{{firewall, 1, 2}}},
		{"alf system_id null", func(k *kitTenant) { k.alf = kitFieldTo(k.alf, "system_id", nil) },
			[]metric{{firewall, 1, 2}}},
		{"alf global_state null", func(k *kitTenant) { k.alf = kitFieldTo(k.alf, "global_state", nil) },
			[]metric{{firewall, 1, 2}}},
		{"windows_security_center collection_time dropped", func(k *kitTenant) { k.securityCenter = kitFieldTo(k.securityCenter, "collection_time", kitDropped{}) },
			[]metric{{firewall, 1, 2}}},
		{"windows_security_center system_id null", func(k *kitTenant) { k.securityCenter = kitFieldTo(k.securityCenter, "system_id", nil) },
			[]metric{{firewall, 1, 2}}},
		{"windows_security_center firewall null", func(k *kitTenant) { k.securityCenter = kitFieldTo(k.securityCenter, "firewall", nil) },
			[]metric{{firewall, 1, 2}}},
		{"windows_security_products collection_time null", func(k *kitTenant) { k.products = kitFieldTo(k.products, "collection_time", nil) },
			[]metric{{installed, 1, 3}, {healthy, 1, 3}}},
		{"windows_security_products system_id null", func(k *kitTenant) { k.products = kitFieldTo(k.products, "system_id", nil) },
			[]metric{{installed, 1, 3}, {healthy, 1, 3}}},
		{"windows_security_products type null", func(k *kitTenant) { k.products = kitFieldTo(k.products, "type", nil) },
			[]metric{{installed, 1, 3}, {healthy, 1, 3}}},
		{"windows_security_products state null", func(k *kitTenant) { k.products = kitFieldTo(k.products, "state", nil) },
			[]metric{{healthy, 1, 3}}},
		{"windows_security_products signatures_up_to_date dropped", func(k *kitTenant) {
			k.products = kitFieldTo(k.products, "signatures_up_to_date", kitDropped{})
		}, []metric{{healthy, 1, 3}}},
		{"systems lastContact a month old", func(k *kitTenant) { k.systems = kitFieldTo(k.systems, "lastContact", "2026-09-01T00:00:00.000Z") },
			[]metric{{disk, 0, 2}}},
		{"alf global_state unrecognized", func(k *kitTenant) { k.alf = kitFieldTo(k.alf, "global_state", 7) },
			[]metric{{firewall, 0, 2}}},
		{"systems without the agent or fde", func(k *kitTenant) {
			k.systems = kitFieldTo(kitFieldTo(k.systems, "agentVersion", kitDropped{}), "fde", kitDropped{})
		}, []metric{{disk, 0, 2}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tenant := kitCleanTenant()
			tc.edit(&tenant)
			res := kitRun(t, kitConfig(), tenant.responses())
			for _, m := range tc.metrics {
				pct := m.summary + "/passing_pct"
				if m.unmeasured > 0 {
					kitWantPartial(t, res, detailedPath, pct, false, m.unmeasured)
					kitWantPartial(t, res, endpointPosturePath, m.pointer, true, m.unmeasured)
				} else {
					if v, _ := kitAt(t, res, detailedPath, pct); v == nil {
						t.Errorf("%s is null, want it over the devices that passed or failed", pct)
					}
					if _, ok := kitAt(t, res, endpointPosturePath, m.pointer); !ok {
						t.Errorf("%s left out, want it over the devices that passed or failed", m.pointer)
					}
					for _, at := range []componentsdk.Location{detailed(pct), endpoint(m.pointer)} {
						if g, ok := kitGap(res, at.Path, at.Pointer); ok {
							t.Errorf("gap at %s %s = %+v, want none", at.Path, at.Pointer, g)
						}
					}
				}
				for _, at := range []componentsdk.Location{
					detailed(m.summary + "/unknown_devices_count"),
					endpoint("/metric_coverage/" + m.path + "/unknown_device_count"),
				} {
					if v, _ := kitAt(t, res, at.Path, at.Pointer); v != float64(m.unknown) {
						t.Errorf("%s %s = %v, want %d", at.Path, at.Pointer, v, m.unknown)
					}
				}
			}
			for _, check := range res.Result.Checks {
				t.Errorf("check finding %+v", check)
			}
		})
	}
}

// A trust run writes no organization, user, or device ID: not in the
// artifacts, their diagnostics, or the collector result. The identity
// artifact names the organization by the users' email domain. An audit run
// writes the organization ID as before.
func TestTrustRunWritesNoAccountIDs(t *testing.T) {
	clean := kitCleanTenant().responses()
	refused := append([]collectortest.Response{kitRefused(kitConsole + "/api/organizations")}, clean...)
	ids := []string{kitOrgID, `"u1"`, `"u2"`, `"a1"`, `"a2"`, "s-mac", "s-win", "s-lin"}
	for name, responses := range map[string][]collectortest.Response{"clean": clean, "organization list refused": refused} {
		trust := kitRun(t, map[string]any{"level": "trust"}, responses)
		for _, artifact := range trust.Artifacts {
			for _, id := range ids {
				if strings.Contains(string(artifact.Data), id) {
					t.Errorf("%s: %s names %s at trust: %s", name, artifact.Path, id, artifact.Data)
				}
			}
		}
		if got := kitField(t, trust, idpPosturePath, "org_domain"); got != "example.com" {
			t.Errorf("%s: org_domain = %v at trust, want the users' email domain", name, got)
		}
		for _, check := range trust.Result.Checks {
			t.Errorf("%s: trust run has check finding %+v", name, check)
		}
	}

	audit := kitRun(t, map[string]any{"level": "audit"}, clean)
	for _, at := range []struct{ path, key string }{
		{detailedPath, "org_id"},
		{idpPosturePath, "org_domain"},
		{endpointPosturePath, "organization_id"},
	} {
		if got := kitField(t, audit, at.path, at.key); got != kitOrgID {
			t.Errorf("%s %s = %v at audit, want %s", at.path, at.key, got, kitOrgID)
		}
	}
}

// The run declares the organization as the whole detailed artifact, named
// by its org_id and labeled by its org_name, the display name. Only the
// audit level holds either. It is chosen by org_id when the config names
// one, and found by the API key otherwise. From the audit level, a run that
// could not read the organization leaves org_name out with a gap, so the
// organization is incomplete and the run partial. A trust run writes
// neither value nor gap, so the same run is collected.
func TestRunDeclaresTheOrganization(t *testing.T) {
	one, complete, incomplete := 1, true, false
	declared := func(chosen componentsdk.TargetChoice, key string, count *int, done *bool) []componentsdk.ResultTarget {
		return []componentsdk.ResultTarget{{
			Kind: componentsdk.TargetOrganization, ChosenBy: chosen, ConfigKey: key,
			At:   &componentsdk.Location{Path: detailedPath, Pointer: ""},
			Name: []string{"/org_id"}, Label: "/org_name", Count: count, Complete: done,
		}}
	}
	clean := kitCleanTenant().responses()
	refused := append([]collectortest.Response{kitRefused(kitConsole + "/api/organizations")}, clean...)
	cases := []struct {
		name      string
		config    map[string]any
		responses []collectortest.Response
		want      []componentsdk.ResultTarget
		orgName   any
		gap       bool
		status    string
	}{
		{
			name: "audit, found by the key", config: map[string]any{"level": "audit"}, responses: clean,
			want: declared(componentsdk.ChosenByDiscovery, "", &one, &complete), orgName: "Example Org",
			status: componentsdk.OutcomeCollected,
		},
		{
			name: "audit, named by org_id", config: map[string]any{"level": "audit", "org_id": kitOrgID}, responses: clean,
			want: declared(componentsdk.ChosenByConfig, "org_id", &one, &complete), orgName: "Example Org",
			status: componentsdk.OutcomeCollected,
		},
		{
			name: "trust, found by the key", config: map[string]any{"level": "trust"}, responses: clean,
			want:   declared(componentsdk.ChosenByDiscovery, "", nil, &complete),
			status: componentsdk.OutcomeCollected,
		},
		{
			name: "trust, named by org_id", config: map[string]any{"level": "trust", "org_id": kitOrgID}, responses: clean,
			want:   declared(componentsdk.ChosenByConfig, "org_id", nil, &complete),
			status: componentsdk.OutcomeCollected,
		},
		{
			name: "audit, organization list refused", config: map[string]any{"level": "audit"}, responses: refused,
			want: declared(componentsdk.ChosenByDiscovery, "", &one, &incomplete), gap: true,
			status: componentsdk.OutcomePartial,
		},
		{
			name: "trust, organization list refused", config: map[string]any{"level": "trust"}, responses: refused,
			want:   declared(componentsdk.ChosenByDiscovery, "", nil, &complete),
			status: componentsdk.OutcomeCollected,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := kitRun(t, tc.config, tc.responses)
			if !reflect.DeepEqual(res.Result.Targets, tc.want) {
				got, _ := json.Marshal(res.Result.Targets)
				want, _ := json.Marshal(tc.want)
				t.Errorf("targets = %s, want %s", got, want)
			}
			for _, check := range res.Result.Checks {
				t.Errorf("check finding %+v", check)
			}
			if got := kitField(t, res, detailedPath, "org_name"); got != tc.orgName {
				t.Errorf("org_name = %v, want %v", got, tc.orgName)
			}
			var gaps []componentsdk.Gap
			for _, g := range res.Result.Gaps {
				if g.Path == detailedPath && g.Pointer == "/org_name" {
					gaps = append(gaps, g)
				}
			}
			wantGaps := 0
			if tc.gap {
				wantGaps = 1
			}
			if len(gaps) != wantGaps || tc.gap && gaps[0].Code != componentsdk.CodePermissionDenied {
				t.Errorf("gaps at /org_name = %+v, want %d permission_denied", gaps, wantGaps)
			}
			if res.Result.Outcome.Status != tc.status {
				t.Errorf("outcome = %+v, want %s", res.Result.Outcome, tc.status)
			}
		})
	}
}
