package jumpcloud

import "time"

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
// Note: the presence of sso.type indicates SSO is configured. The "active"
// field may not be present in all JumpCloud API versions; callers should
// treat a non-empty sso.type as evidence of SSO enablement.
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

// Administrator represents a JumpCloud admin portal administrator.
type Administrator struct {
	ID                string `json:"_id"`
	Email             string `json:"email"`
	EnableMultiFactor bool   `json:"enableMultiFactor"`
	TOTPEnabled       bool   `json:"totpEnabled"`
	RoleName          string `json:"roleName"`
	Created           string `json:"created"`
}

// System represents a managed device from the V1 /api/systems endpoint.
type System struct {
	ID           string     `json:"_id"`
	Hostname     string     `json:"hostname"`
	DisplayName  string     `json:"displayName"`
	OS           string     `json:"os"`
	OSVersion    string     `json:"osVersion"`
	AgentVersion string     `json:"agentVersion"`
	Active       bool       `json:"active"`
	LastContact  *time.Time `json:"lastContact"`
	MDM          *SystemMDM `json:"mdm"`
}

// SystemMDM holds MDM enrollment info for a system.
type SystemMDM struct {
	Internal *MDMInternal `json:"internal"`
}

// MDMInternal holds internal MDM fields.
type MDMInternal struct {
	DeviceID string `json:"deviceId"`
}

// HasMDM returns true when the system has MDM enrollment evidence.
// Since the documented MDM shape may vary, we check for the presence of
// the internal deviceId as evidence of enrollment.
func (s *System) HasMDM() bool {
	return s.MDM != nil && s.MDM.Internal != nil && s.MDM.Internal.DeviceID != ""
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
	ID         string             `json:"id"`
	Name       string             `json:"name"`
	Disabled   bool               `json:"disabled"`
	Type       string             `json:"type"`
	Effect     *AuthPolicyEffect  `json:"effect"`
	Conditions *AuthPolicyConditions `json:"conditions"`
}

// AuthPolicyEffect holds the effect/obligations of an auth policy.
type AuthPolicyEffect struct {
	Action      string             `json:"action"`
	Obligations *PolicyObligations `json:"obligations"`
}

// PolicyObligations holds MFA and other requirements.
type PolicyObligations struct {
	MFA        *PolicyMFA        `json:"mfa"`
	MFAFactors []MFAFactorEntry  `json:"mfaFactors"`
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

// AuthPolicyConditions holds conditions for policy evaluation.
type AuthPolicyConditions struct {
	DeviceManaged *BoolCondition `json:"deviceManaged"`
	IPAddress     *IPAddressCondition `json:"ipAddress"`
}

// BoolCondition is a generic boolean condition.
type BoolCondition struct {
	Value bool `json:"value"`
}

// IPAddressCondition holds network-based conditions.
type IPAddressCondition struct {
	TrustedOnly bool `json:"trustedOnly"`
}

// DirectoryInsightsEvent represents a single event from the Directory Insights API.
type DirectoryInsightsEvent struct {
	ID        string      `json:"id"`
	EventType string      `json:"event_type"`
	Service   string      `json:"service"`
	Timestamp string      `json:"timestamp"`
	InitiatedBy *EventActor `json:"initiated_by"`
}

// EventActor identifies who initiated an event.
type EventActor struct {
	Type  string `json:"type"`
	Email string `json:"email"`
}
