package collector

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/locktivity/epack/componentsdk/collectortest"
)

const (
	kitAPIKey  = "kit-jumpcloud-api-key-0123456789"
	kitConsole = "https://console.jumpcloud.com"
	kitAPI     = "https://api.jumpcloud.com"
	kitOrgID   = "org-kit"
)

// kitNow is the time the kit's runs see. The device readings below are a
// few hours older.
var kitNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func kitConfig() map[string]any {
	return map[string]any{"level": "internal"}
}

func kitSecrets() map[string]string {
	return map[string]string{apiKeyEnv: kitAPIKey}
}

// kitV1 is a V1 list page holding every row, with its total.
func kitV1(total int, rows ...string) string {
	return `{"totalCount": ` + strconv.Itoa(total) + `, "results": [` + strings.Join(rows, ",") + `]}`
}

// There are five users. Three can sign in, one is suspended, and one is
// staged. Alice has TOTP and WebAuthn, and Blake has push. Casey has no MFA
// and is locked out.
var kitUserRows = []string{
	`{"_id": "u1", "username": "alice", "email": "alice@example.com", "state": "ACTIVATED", "organization": "org-kit",
	  "account_locked": false, "suspended": false, "totp_enabled": true, "enable_user_portal_multifactor": true,
	  "mfa": {"configured": true, "exclusion": false},
	  "mfaEnrollment": {"overallStatus": "ENROLLED", "totpStatus": "ENROLLED", "webAuthnStatus": "ENROLLED", "pushStatus": "NOT_ENROLLED"},
	  "created": "2025-01-10T09:00:00.000Z"}`,
	`{"_id": "u2", "username": "blake", "email": "blake@example.com", "state": "ACTIVATED", "organization": "org-kit",
	  "account_locked": false, "suspended": false, "totp_enabled": false, "enable_user_portal_multifactor": false,
	  "mfa": {"configured": true, "exclusion": false},
	  "mfaEnrollment": {"overallStatus": "ENROLLED", "totpStatus": "NOT_ENROLLED", "webAuthnStatus": "NOT_ENROLLED", "pushStatus": "ENROLLED"},
	  "created": "2025-02-11T09:00:00.000Z"}`,
	`{"_id": "u3", "username": "casey", "email": "casey@example.com", "state": "ACTIVATED", "organization": "org-kit",
	  "account_locked": true, "suspended": false, "totp_enabled": false, "enable_user_portal_multifactor": false,
	  "mfa": {"configured": false, "exclusion": false},
	  "created": "2025-03-12T09:00:00.000Z"}`,
	`{"_id": "u4", "username": "drew", "email": "drew@example.com", "state": "SUSPENDED", "organization": "org-kit",
	  "account_locked": false, "suspended": true, "totp_enabled": false, "enable_user_portal_multifactor": false,
	  "created": "2024-04-13T09:00:00.000Z"}`,
	`{"_id": "u5", "username": "emery", "email": "emery@example.com", "state": "STAGED", "organization": "org-kit",
	  "account_locked": false, "suspended": false, "totp_enabled": false, "enable_user_portal_multifactor": false,
	  "created": "2026-09-30T09:00:00.000Z"}`,
}

const kitOrgRow = `{"_id": "org-kit", "displayName": "Example Org"}`

// Two of the three applications have SSO set up.
var kitAppRows = []string{
	`{"_id": "app1", "name": "slack", "displayName": "Slack", "displayLabel": "Slack", "sso": {"type": "saml"}}`,
	`{"_id": "app2", "name": "github", "displayName": "GitHub", "displayLabel": "GitHub", "sso": {"type": "oidc"}}`,
	`{"_id": "app3", "name": "bookmark", "displayName": "Wiki bookmark", "displayLabel": "Wiki"}`,
}

// Both administrators have TOTP enrolled, and one holds the billing role.
var kitAdminRows = []string{
	`{"_id": "a1", "email": "owner@example.com", "enableMultiFactor": true, "totpEnrolled": true, "roleName": "Administrator With Billing", "created": "2024-01-01T00:00:00.000Z"}`,
	`{"_id": "a2", "email": "ops@example.com", "enableMultiFactor": false, "totpEnrolled": true, "roleName": "Administrator", "created": "2024-06-01T00:00:00.000Z"}`,
}

const kitPolicies = `[
	{"id": "p1", "name": "User Portal MFA", "type": "user_portal", "disabled": false,
	 "effect": {"action": "allow", "obligations": {"mfa": {"required": true}}}},
	{"id": "p2", "name": "Admin Portal keys only", "type": "admin_portal", "disabled": false,
	 "effect": {"action": "allow", "obligations": {"mfa": {"required": true}, "mfaFactors": [{"type": "WEBAUTHN"}, {"type": "FIDO2"}]}}},
	{"id": "p3", "name": "Managed devices for SSO", "type": "sso", "disabled": false,
	 "effect": {"action": "allow"}, "conditions": {"all": [{"deviceManaged": true}]}},
	{"id": "p4", "name": "Old policy", "type": "user_portal", "disabled": true,
	 "effect": {"action": "allow", "obligations": {"mfa": {"required": true}}}}
]`

// A Mac, a Windows PC, and a Linux server. The Mac and the PC are encrypted
// and the server is not.
var kitSystemRows = []string{
	`{"_id": "s-mac", "hostname": "mac-01", "displayName": "mac-01", "os": "Mac OS X", "osFamily": "darwin", "version": "15.1",
	  "agentVersion": "2.1.0", "active": true, "created": "2025-01-10T09:00:00.000Z", "lastContact": "2026-10-01T11:30:00.000Z",
	  "mdm": {"vendor": "internal", "internal": {"deviceId": "mdm-mac-01"}}, "fde": {"active": true, "keyPresent": true},
	  "primarySystemUser": {"id": "u1"}}`,
	`{"_id": "s-win", "hostname": "win-01", "displayName": "win-01", "os": "Windows", "osFamily": "windows", "version": "11",
	  "agentVersion": "2.1.0", "active": true, "created": "2025-02-11T09:00:00.000Z", "lastContact": "2026-10-01T11:00:00.000Z",
	  "mdm": {"vendor": "internal", "internal": {"windowsDeviceId": "mdm-win-01"}}, "fde": {"active": true, "keyPresent": true},
	  "primarySystemUser": {"id": "u2"}}`,
	`{"_id": "s-lin", "hostname": "lin-01", "displayName": "lin-01", "os": "Ubuntu", "osFamily": "linux", "version": "24.04",
	  "agentVersion": "2.1.0", "active": false, "created": "2025-03-12T09:00:00.000Z", "lastContact": "2026-10-01T10:00:00.000Z",
	  "fde": {"active": false, "keyPresent": false}}`,
}

const (
	kitBitLocker = `[{"system_id": "s-win", "collection_time": "2026-10-01 09:00:00 +0000", "device_id": "\\\\?\\Volume{1}\\",
		"drive_letter": "C:", "protection_status": 1, "conversion_status": 1}]`
	kitSecurityCenter = `[{"system_id": "s-win", "collection_time": "2026-10-01 09:00:00 +0000", "firewall": "Good"}]`
	kitProducts       = `[
		{"system_id": "s-win", "collection_time": "2026-10-01 09:00:00 +0000", "type": "Antivirus", "state": "On", "signatures_up_to_date": 1},
		{"system_id": "s-win", "collection_time": "2026-10-01 09:00:00 +0000", "type": "Firewall", "state": "On", "signatures_up_to_date": 1}
	]`
	kitALF          = `[{"system_id": "s-mac", "collection_time": "2026-10-01 09:00:00 +0000", "global_state": 1}]`
	kitInsightUsers = `[
		{"system_id": "s-mac", "collection_time": "2026-10-01 09:00:00 +0000", "username": "alice", "uid": "501", "admin": true},
		{"system_id": "s-mac", "collection_time": "2026-10-01 09:00:00 +0000", "username": "guest", "uid": "502", "admin": false},
		{"system_id": "s-win", "collection_time": "2026-10-01 09:00:00 +0000", "username": "Administrator", "uid": "500", "admin": true}
	]`
	kitUserGroups   = `[{"id": "ug1", "name": "Engineering", "type": "user_group"}, {"id": "ug2", "name": "Finance", "type": "user_group"}]`
	kitSystemGroups = `[{"id": "sg1", "name": "Workstations", "type": "system_group"}]`
	kitEvents       = `[
		{"id": "e1", "event_type": "admin_login_attempt", "service": "directory", "timestamp": "2026-09-30T08:00:00Z", "initiated_by": {"type": "admin", "email": "owner@example.com"}},
		{"id": "e2", "event_type": "user_update", "service": "directory", "timestamp": "2026-09-30T09:00:00Z", "initiated_by": {"type": "admin", "email": "ops@example.com"}},
		{"id": "e3", "event_type": "user_update", "service": "directory", "timestamp": "2026-09-30T10:00:00Z"}
	]`
)

// kitTenant answers every call a clean run makes, with the users, the
// systems, and the organizations given.
type kitTenant struct {
	users, orgs, apps, admins, systems  string
	policies, userGroups, systemGroups  string
	bitlocker, securityCenter, products string
	alf, insightUsers, events           string
}

func kitCleanTenant() kitTenant {
	return kitTenant{
		users:          kitV1(len(kitUserRows), kitUserRows...),
		orgs:           kitV1(1, kitOrgRow),
		apps:           kitV1(len(kitAppRows), kitAppRows...),
		admins:         kitV1(len(kitAdminRows), kitAdminRows...),
		systems:        kitV1(len(kitSystemRows), kitSystemRows...),
		policies:       kitPolicies,
		userGroups:     kitUserGroups,
		systemGroups:   kitSystemGroups,
		bitlocker:      kitBitLocker,
		securityCenter: kitSecurityCenter,
		products:       kitProducts,
		alf:            kitALF,
		insightUsers:   kitInsightUsers,
		events:         kitEvents,
	}
}

// kitEmptyTenant is an organization with nothing in it.
func kitEmptyTenant() kitTenant {
	t := kitCleanTenant()
	t.users, t.apps, t.admins, t.systems = kitV1(0), kitV1(0), kitV1(0), kitV1(0)
	t.policies, t.userGroups, t.systemGroups, t.events = `[]`, `[]`, `[]`, `[]`
	return t
}

func (t kitTenant) responses() []collectortest.Response {
	return []collectortest.Response{
		{URL: kitConsole + "/api/systemusers", Body: t.users},
		{URL: kitConsole + "/api/organizations", Body: t.orgs},
		{URL: kitConsole + "/api/applications", Body: t.apps},
		{URL: kitConsole + "/api/users", Body: t.admins},
		{URL: kitConsole + "/api/v2/authn/policies", Body: t.policies},
		{URL: kitConsole + "/api/systems", Body: t.systems},
		{URL: kitConsole + "/api/v2/systeminsights/bitlocker_info", Body: t.bitlocker},
		{URL: kitConsole + "/api/v2/systeminsights/windows_security_center", Body: t.securityCenter},
		{URL: kitConsole + "/api/v2/systeminsights/windows_security_products", Body: t.products},
		{URL: kitConsole + "/api/v2/systeminsights/alf", Body: t.alf},
		{URL: kitConsole + "/api/v2/systeminsights/users", Body: t.insightUsers},
		{URL: kitConsole + "/api/v2/usergroups", Body: t.userGroups},
		{URL: kitConsole + "/api/v2/systemgroups", Body: t.systemGroups},
		{Method: http.MethodPost, URL: kitAPI + "/insights/directory/v1/events", Body: t.events},
	}
}

// kitDropped is the value kitFieldTo gives a field it leaves out.
type kitDropped struct{}

// kitFieldTo returns the JSON body with every field at field set to value,
// or left out when value is kitDropped{}. field is a key, or keys joined by
// "/" for a key inside another, such as "fde/active". It matches at any
// depth.
func kitFieldTo(body, field string, value any) string {
	dec := json.NewDecoder(strings.NewReader(body))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		panic("kit fixture: " + err.Error())
	}
	path := strings.Split(field, "/")
	var walk func(v any, at []string)
	walk = func(v any, at []string) {
		switch v := v.(type) {
		case map[string]any:
			for key, child := range v {
				switch {
				case key != at[0]:
					walk(child, path)
				case len(at) > 1:
					walk(child, at[1:])
				case value == kitDropped{}:
					delete(v, key)
				default:
					v[key] = value
				}
			}
		case []any:
			for _, child := range v {
				walk(child, path)
			}
		}
	}
	walk(doc, path)
	out, err := json.Marshal(doc)
	if err != nil {
		panic("kit fixture: " + err.Error())
	}
	return string(out)
}

// kitRefused answers url with a 403, the status for a read the API key's
// role does not allow.
func kitRefused(url string) collectortest.Response {
	return collectortest.Response{URL: url, Status: http.StatusForbidden, Body: `{"message":"Forbidden"}`}
}
