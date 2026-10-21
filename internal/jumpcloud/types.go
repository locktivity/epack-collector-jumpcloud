package jumpcloud

import (
	"encoding/json"
)

// SystemUser represents a user from the V1 /api/systemusers endpoint.
type SystemUser struct {
	ID                          string         `json:"_id"`
	Username                    string         `json:"username"`
	Email                       string         `json:"email"`
	Firstname                   string         `json:"firstname"`
	Lastname                    string         `json:"lastname"`
	Displayname                 string         `json:"displayname"`
	State                       string         `json:"state"`
	AccountLocked               bool           `json:"account_locked"`
	Suspended                   bool           `json:"suspended"`
	TOTPEnabled                 bool           `json:"totp_enabled"`
	EnableUserPortalMultifactor bool           `json:"enable_user_portal_multifactor"`
	MFA                         *MFAConfig     `json:"mfa"`
	MFAEnrollment               *MFAEnrollment `json:"mfaEnrollment"`
	Created                     string         `json:"created"`
	ExternallyManaged           bool           `json:"externally_managed"`
	PasswordExpirationDate      string         `json:"password_expiration_date"`
}

// MFAConfig holds MFA configuration flags.
type MFAConfig struct {
	Configured bool `json:"configured"`
	Exclusion  bool `json:"exclusion"`
}

// MFAEnrollment holds per-factor enrollment status.
type MFAEnrollment struct {
	OverallStatus  string `json:"overallStatus"`
	TOTPStatus     string `json:"totpStatus"`
	WebAuthnStatus string `json:"webAuthnStatus"`
	PushStatus     string `json:"pushStatus"`
	SMSStatus      string `json:"smsStatus"`
	JCGoStatus     string `json:"jcGoStatus"`
}

// HasAnyMFA returns true when the user has at least one MFA method enrolled.
func (e *MFAEnrollment) HasAnyMFA() bool {
	if e == nil {
		return false
	}
	return e.TOTPStatus == "ENROLLED" ||
		e.WebAuthnStatus == "ENROLLED" ||
		e.PushStatus == "ENROLLED" ||
		e.SMSStatus == "ENROLLED" ||
		e.JCGoStatus == "ENROLLED"
}

// HasPhishingResistantMFA returns true when the user has a phishing-resistant
// method (WebAuthn/FIDO2) enrolled.
func (e *MFAEnrollment) HasPhishingResistantMFA() bool {
	if e == nil {
		return false
	}
	return e.WebAuthnStatus == "ENROLLED"
}

// Application represents an SSO application from the V1 /api/applications endpoint.
type Application struct {
	ID           string          `json:"_id"`
	Name         string          `json:"name"`
	DisplayName  string          `json:"displayName"`
	DisplayLabel string          `json:"displayLabel"`
	SSO          *ApplicationSSO `json:"sso"`
}

// ApplicationSSO holds SSO configuration for an application.
type ApplicationSSO struct {
	Type string `json:"type"`
}

// IsSSOEnabled returns true when the application has an SSO type configured.
func (a *Application) IsSSOEnabled() bool {
	return a.SSO != nil && a.SSO.Type != ""
}

// Organization represents a JumpCloud organization.
type Organization struct {
	ID          string `json:"_id"`
	DisplayName string `json:"displayName"`
}

// Administrator is an Admin Portal administrator from V1 /api/users, which
// lists administrators (directory users are /api/systemusers).
type Administrator struct {
	ID                string `json:"_id"`
	Email             string `json:"email"`
	EnableMultiFactor bool   `json:"enableMultiFactor"`
	TOTPEnrolled      bool   `json:"totpEnrolled"`
	RoleName          string `json:"roleName"`
	Created           string `json:"created"`
}

// System represents a managed device from the V1 /api/systems endpoint.
type System struct {
	ID                string                `json:"_id"`
	Hostname          string                `json:"hostname"`
	DisplayName       string                `json:"displayName"`
	OS                string                `json:"os"`
	OSFamily          string                `json:"osFamily"`
	Version           string                `json:"version"`
	OSVersionDetail   *OSVersionDetail      `json:"osVersionDetail"`
	AgentVersion      string                `json:"agentVersion"`
	Active            bool                  `json:"active"`
	Created           string                `json:"created"`
	LastContact       string                `json:"lastContact"`
	MDM               *SystemMDM            `json:"mdm"`
	FDE               *SystemFDE            `json:"fde"`
	PrimarySystemUser *PrimarySystemUserRef `json:"primarySystemUser"`
}

// OSVersionDetail is the agent's structured OS version report.
type OSVersionDetail struct {
	OSName  string `json:"osName"`
	Version string `json:"version"`
}

// SystemFDE is the agent's full-disk-encryption report. Active is a pointer
// because an absent reading is unknown, not unencrypted. keyPresent is not
// modeled: key escrow is not evidence of encryption.
type SystemFDE struct {
	Active *bool `json:"active"`
}

// PrimarySystemUserRef identifies the device's designated primary user.
type PrimarySystemUserRef struct {
	ID string `json:"id"`
}

// OSVersionString returns the reported OS version, preferring the top-level
// field and falling back to the structured detail.
func (s *System) OSVersionString() string {
	if s.Version != "" {
		return s.Version
	}
	if s.OSVersionDetail != nil {
		return s.OSVersionDetail.Version
	}
	return ""
}

// SystemMDM holds MDM enrollment info for a system. The shape varies by
// platform: macOS/iOS uses internal.deviceId, Windows uses
// internal.windowsDeviceId, and third-party MDMs populate vendor fields.
type SystemMDM struct {
	Vendor   string       `json:"vendor"`
	Internal *MDMInternal `json:"internal"`
}

// MDMInternal holds internal MDM device IDs.
type MDMInternal struct {
	DeviceID        string `json:"deviceId"`
	WindowsDeviceID string `json:"windowsDeviceId"`
}

// HasMDM returns true when the system shows evidence of MDM enrollment
// across any supported platform or vendor. Vendor values "none" and
// "unknown" do not constitute enrollment evidence.
func (s *System) HasMDM() bool {
	if s.MDM == nil {
		return false
	}
	if isEnrolledVendor(s.MDM.Vendor) {
		return true
	}
	if s.MDM.Internal == nil {
		return false
	}
	return s.MDM.Internal.DeviceID != "" || s.MDM.Internal.WindowsDeviceID != ""
}

// isEnrolledVendor returns true for vendor values that indicate actual
// MDM management. The documented enum includes "none", "unknown",
// "internal", and "external"; only the latter two prove enrollment.
func isEnrolledVendor(vendor string) bool {
	switch vendor {
	case "internal", "external":
		return true
	default:
		return false
	}
}

// UserGroup represents a user group from the V2 API.
type UserGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// SystemGroup represents a system group from the V2 API.
type SystemGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// AuthPolicy represents an authentication policy from the V2 authn/policies
// endpoint. The response is a bare array (not wrapped in {results}).
type AuthPolicy struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Disabled   bool              `json:"disabled"`
	Type       string            `json:"type"`
	Effect     *AuthPolicyEffect `json:"effect"`
	Conditions json.RawMessage   `json:"conditions"`
}

// AuthPolicyEffect holds the effect/obligations of an auth policy.
type AuthPolicyEffect struct {
	Action      string             `json:"action"`
	Obligations *PolicyObligations `json:"obligations"`
}

// PolicyObligations holds MFA and other requirements.
type PolicyObligations struct {
	MFA              *PolicyMFA        `json:"mfa"`
	MFAFactors       []MFAFactorEntry  `json:"mfaFactors"`
	UserVerification *UserVerification `json:"userVerification"`
}

// MFAFactorEntry represents one allowed MFA factor. JumpCloud represents
// factors as objects with a "type" key, e.g. {"type":"WEBAUTHN"}.
type MFAFactorEntry struct {
	Type string `json:"type"`
}

// PolicyMFA holds MFA requirement flag.
type PolicyMFA struct {
	Required bool `json:"required"`
}

// UserVerification holds user verification requirements.
type UserVerification struct {
	Requirement string `json:"requirement"`
}

// ConditionHasDeviceManaged inspects the raw conditions JSON for a
// deviceManaged condition. The actual API uses a boolean value directly
// (e.g. {"deviceManaged":true}), but conditions can also be nested inside
// all/any/not expressions. This performs a best-effort check: it returns
// true when deviceManaged appears as a top-level boolean or anywhere in
// the condition tree, and false when conditions are absent or unparseable.
func (p *AuthPolicy) ConditionHasDeviceManaged() bool {
	if len(p.Conditions) == 0 {
		return false
	}
	return rawContainsDeviceManaged(p.Conditions)
}

func rawContainsDeviceManaged(raw json.RawMessage) bool {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return false
	}

	if dm, ok := obj["deviceManaged"]; ok {
		var v bool
		if json.Unmarshal(dm, &v) == nil && v {
			return true
		}
	}

	for _, key := range []string{"all", "any"} {
		if sub, ok := obj[key]; ok {
			var items []json.RawMessage
			if json.Unmarshal(sub, &items) == nil {
				for _, item := range items {
					if rawContainsDeviceManaged(item) {
						return true
					}
				}
			}
		}
	}

	if notRaw, ok := obj["not"]; ok {
		if rawContainsDeviceManaged(notRaw) {
			return true
		}
	}

	return false
}

// System Insights rows (V2 /systeminsights/<table>). Each table is an
// osquery-backed snapshot with one or more rows per system. Nullable columns
// are pointers so a missing reading stays distinguishable from zero/false.

// InsightBitLocker is a row from /systeminsights/bitlocker_info.
// protection_status and conversion_status follow Win32_EncryptableVolume:
// protection 0=off, 1=on, 2=unknown; conversion 0=fully decrypted,
// 1=fully encrypted, 2=encrypting, 3=decrypting, 4=encryption paused,
// 5=decryption paused.
type InsightBitLocker struct {
	SystemID         string  `json:"system_id"`
	CollectionTime   string  `json:"collection_time"`
	DriveLetter      *string `json:"drive_letter"`
	ProtectionStatus *int    `json:"protection_status"`
	ConversionStatus *int    `json:"conversion_status"`
}

// InsightALF is a row from /systeminsights/alf (macOS Application Layer
// Firewall). global_state: 0=off, 1=on, 2=on and blocking all incoming.
type InsightALF struct {
	SystemID       string `json:"system_id"`
	CollectionTime string `json:"collection_time"`
	GlobalState    *int   `json:"global_state"`
}

// InsightWindowsSecurityCenter is a row from
// /systeminsights/windows_security_center. Health strings are Windows
// Security Center states: Good, Poor, Snoozed, Not Monitored, Error.
type InsightWindowsSecurityCenter struct {
	SystemID       string  `json:"system_id"`
	CollectionTime string  `json:"collection_time"`
	Firewall       *string `json:"firewall"`
}

// InsightWindowsSecurityProduct is a row from
// /systeminsights/windows_security_products. remediation_path is
// deliberately not modeled.
type InsightWindowsSecurityProduct struct {
	SystemID           string   `json:"system_id"`
	CollectionTime     string   `json:"collection_time"`
	Type               *string  `json:"type"`
	State              *string  `json:"state"`
	SignaturesUpToDate *float64 `json:"signatures_up_to_date"`
}

// InsightUser is a row from /systeminsights/users. Home directory, shell,
// and other account detail are deliberately not modeled.
type InsightUser struct {
	SystemID       string  `json:"system_id"`
	CollectionTime string  `json:"collection_time"`
	Username       *string `json:"username"`
	UID            *string `json:"uid"`
	Admin          *bool   `json:"admin"`
}

// DirectoryInsightsEvent represents a single event from the Directory Insights API.
type DirectoryInsightsEvent struct {
	ID          string      `json:"id"`
	EventType   string      `json:"event_type"`
	Service     string      `json:"service"`
	Timestamp   string      `json:"timestamp"`
	InitiatedBy *EventActor `json:"initiated_by"`
}

// EventActor identifies who initiated an event.
type EventActor struct {
	Type  string `json:"type"`
	Email string `json:"email"`
}
