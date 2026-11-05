package jumpcloud

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

// The two JumpCloud API hosts, the only hosts the client sends the API key
// to.
const (
	// ConsoleHost serves the V1 and V2 management APIs.
	ConsoleHost = "console.jumpcloud.com"
	// InsightsHost serves the Directory Insights API.
	InsightsHost = "api.jumpcloud.com"
)

const (
	consoleBaseURL  = "https://" + ConsoleHost
	insightsBaseURL = "https://" + InsightsHost

	maxPerPage = 100
	// MaxResults is the most rows the client reads from a V1 or V2 list.
	MaxResults = 50000

	insightsPageSize = 1000
	// MaxInsightRows is the most rows the client reads from a System
	// Insights table. Insights tables hold several rows per system, so the
	// limit is higher than MaxResults.
	MaxInsightRows = 250000

	maxResponseBytes = 64 << 20
	maxErrorBytes    = 4 << 10
)

// Operation names, one per API call. They count each call in the collector
// result and key the test kit's fault matrix and the trace map, so rename
// one only on purpose.
const (
	OpListSystemUsers             = "jumpcloud.systemusers.list"
	OpListOrganizations           = "jumpcloud.organizations.list"
	OpListApplications            = "jumpcloud.applications.list"
	OpListAdministrators          = "jumpcloud.administrators.list"
	OpListAuthPolicies            = "jumpcloud.authn_policies.list"
	OpListSystems                 = "jumpcloud.systems.list"
	OpListBitLocker               = "jumpcloud.systeminsights.bitlocker_info.list"
	OpListWindowsSecurityCenter   = "jumpcloud.systeminsights.windows_security_center.list"
	OpListWindowsSecurityProducts = "jumpcloud.systeminsights.windows_security_products.list"
	OpListALF                     = "jumpcloud.systeminsights.alf.list"
	OpListInsightUsers            = "jumpcloud.systeminsights.users.list"
	OpListUserGroups              = "jumpcloud.usergroups.list"
	OpListSystemGroups            = "jumpcloud.systemgroups.list"
	OpQueryEvents                 = "jumpcloud.directory_insights.events.query"
)

// permissions holds the read-only scope JumpCloud's API reference lists for
// each call, as its x-scopes. A service account or a custom admin role
// grants these. JumpCloud's reference does not document /api/users, so the
// administrators call has none.
var permissions = map[string]string{
	OpListSystemUsers:             "users.readonly",
	OpListOrganizations:           "organizations.readonly",
	OpListApplications:            "applications.readonly",
	OpListAuthPolicies:            "authn.readonly",
	OpListSystems:                 "systems.readonly",
	OpListBitLocker:               "systeminsights.readonly",
	OpListWindowsSecurityCenter:   "systeminsights.readonly",
	OpListWindowsSecurityProducts: "systeminsights.readonly",
	OpListALF:                     "systeminsights.readonly",
	OpListInsightUsers:            "systeminsights.readonly",
	OpListUserGroups:              "groups.readonly",
	OpListSystemGroups:            "groups.readonly",
	OpQueryEvents:                 "directoryinsights.readonly",
}

// Permission returns the scope JumpCloud's API reference lists for the call
// op names, or "" when it lists none.
func Permission(op string) string { return permissions[op] }

var (
	ErrUnauthorized     = errors.New("unauthorized")
	ErrPermissionDenied = errors.New("permission denied")
	ErrNotFound         = errors.New("not found")
)

// APIError is a response whose status is not 2xx. Its message leaves out
// the response body, which can carry untrusted text.
type APIError struct {
	StatusCode int
	Header     http.Header
}

func (e *APIError) Error() string {
	return fmt.Sprintf("JumpCloud API returned status %d", e.StatusCode)
}

// Unwrap lets callers test for the status classes with errors.Is.
func (e *APIError) Unwrap() error {
	switch e.StatusCode {
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusForbidden:
		return ErrPermissionDenied
	case http.StatusNotFound:
		return ErrNotFound
	}
	return nil
}

// HTTPStatus and HTTPHeader let componentsdk.Classify give the error its
// code, such as permission_denied for a 403 or rate_limited for a 429.
func (e *APIError) HTTPStatus() int         { return e.StatusCode }
func (e *APIError) HTTPHeader() http.Header { return e.Header }

// Client is a JumpCloud REST API client for the V1, V2, and Directory
// Insights APIs. Its calls go through the client componentsdk.NewHTTPClient
// returns, which retries the calls it can and sends the API key only to the
// JumpCloud hosts.
type Client struct {
	consoleURL  string
	insightsURL string
	apiKey      string
	orgID       string
	http        *http.Client
}

// NewClient returns a client that reads with apiKey. orgID is optional and
// selects the organization for MSP and multi-tenant keys through the
// x-org-id header.
func NewClient(httpClient *http.Client, apiKey, orgID string) *Client {
	return &Client{
		consoleURL:  consoleBaseURL,
		insightsURL: insightsBaseURL,
		apiKey:      apiKey,
		orgID:       orgID,
		http:        httpClient,
	}
}

// v1Page is one page of a V1 list.
type v1Page[T any] struct {
	TotalCount *int `json:"totalCount"`
	Results    *[]T `json:"results"`
}

// sortByID is the sort sent with each page of a V1 list and of the V2 group
// and policy lists. JumpCloud recommends sorting on _id when paging with
// skip, so that no row is missed or repeated.
const sortByID = "_id"

// listV1 reads every page of a V1 list, sorted by _id. When capped is true
// it stops at MaxResults rows. It returns the rows and the total JumpCloud
// reported. A page without totalCount or results is a malformed response, so
// it never reads as an empty list.
func listV1[T any](ctx context.Context, c *Client, op, path string, capped bool) ([]T, int, error) {
	all := []T{}
	for {
		var page v1Page[T]
		resp, err := c.get(ctx, op, fmt.Sprintf("%s?skip=%d&limit=%d&sort=%s", path, len(all), maxPerPage, sortByID), &page)
		if err != nil {
			return nil, 0, err
		}
		if page.TotalCount == nil || page.Results == nil {
			return nil, 0, componentsdk.ResponseError(resp, invalidResponse(op, "has no totalCount or results"))
		}
		total := *page.TotalCount
		all = append(all, *page.Results...)
		if len(all) >= total || len(*page.Results) < maxPerPage || (capped && len(all) >= MaxResults) {
			return all, total, nil
		}
	}
}

// listV2 reads every page of a V2 list, which is a bare JSON array, up to
// limit rows. When sort is not empty, it is sent with each page. capped is
// true when the limit stopped it before the last page.
func listV2[T any](ctx context.Context, c *Client, op, path, sort string, pageSize, limit int) ([]T, bool, error) {
	all := []T{}
	for {
		var page []T
		query := fmt.Sprintf("%s?skip=%d&limit=%d", path, len(all), pageSize)
		if sort != "" {
			query += "&sort=" + sort
		}
		resp, err := c.get(ctx, op, query, &page)
		if err != nil {
			return nil, false, err
		}
		if page == nil {
			return nil, false, componentsdk.ResponseError(resp, invalidResponse(op, "is null, not a list"))
		}
		all = append(all, page...)
		if len(page) < pageSize {
			return all, false, nil
		}
		if len(all) >= limit {
			return all, true, nil
		}
	}
}

// ListSystemUsers returns the directory users from /api/systemusers and the
// total JumpCloud reported. Fewer users than the total means the list was
// read in part.
func (c *Client) ListSystemUsers(ctx context.Context) ([]SystemUser, int, error) {
	return listV1[SystemUser](ctx, c, OpListSystemUsers, "/api/systemusers", true)
}

// ListApplications returns the SSO applications from /api/applications and
// the total JumpCloud reported.
func (c *Client) ListApplications(ctx context.Context) ([]Application, int, error) {
	return listV1[Application](ctx, c, OpListApplications, "/api/applications", true)
}

// ListAdministrators returns the Admin Portal administrators from
// /api/users and the total JumpCloud reported.
func (c *Client) ListAdministrators(ctx context.Context) ([]Administrator, int, error) {
	return listV1[Administrator](ctx, c, OpListAdministrators, "/api/users", true)
}

// ListSystems returns the managed systems from /api/systems and the total
// JumpCloud reported.
func (c *Client) ListSystems(ctx context.Context) ([]System, int, error) {
	return listV1[System](ctx, c, OpListSystems, "/api/systems", true)
}

// GetOrganization resolves the organization. When orgID is set, as for an
// MSP key, it must match a listed organization. When orgID is empty, it
// returns the sole organization, or nil when none is listed. Several listed
// organizations with no orgID is an error. Every page is read, so the match
// is not limited to the first page.
func (c *Client) GetOrganization(ctx context.Context, orgID string) (*Organization, error) {
	all, _, err := listV1[Organization](ctx, c, OpListOrganizations, "/api/organizations", false)
	if err != nil {
		return nil, fmt.Errorf("getting organizations: %w", err)
	}

	if len(all) == 0 {
		if orgID != "" {
			return nil, &OrgValidationError{
				msg: fmt.Sprintf("configured org_id %q not found: no organizations returned", orgID),
			}
		}
		return nil, nil
	}

	if orgID != "" {
		for i := range all {
			if all[i].ID == orgID {
				return &all[i], nil
			}
		}
		return nil, &OrgValidationError{
			msg: fmt.Sprintf("configured org_id %q not found in organization list", orgID),
		}
	}

	if len(all) > 1 {
		return nil, &OrgValidationError{
			msg: "multiple organizations returned; set org_id to select one",
		}
	}
	return &all[0], nil
}

// OrgValidationError means the organization could not be resolved from the
// configuration. It is a configuration error, so the run fails with
// config_invalid.
type OrgValidationError struct {
	msg string
}

func (e *OrgValidationError) Error() string { return e.msg }

// CollectionCode gives the error the code config_invalid.
func (e *OrgValidationError) CollectionCode() componentsdk.Code {
	return componentsdk.CodeConfigInvalid
}

// ListUserGroups returns the user groups from the V2 API. capped is true
// when MaxResults stopped the read before the last page.
func (c *Client) ListUserGroups(ctx context.Context) ([]UserGroup, bool, error) {
	return listV2[UserGroup](ctx, c, OpListUserGroups, "/api/v2/usergroups", sortByID, maxPerPage, MaxResults)
}

// ListSystemGroups returns the system groups from the V2 API.
func (c *Client) ListSystemGroups(ctx context.Context) ([]SystemGroup, bool, error) {
	return listV2[SystemGroup](ctx, c, OpListSystemGroups, "/api/v2/systemgroups", sortByID, maxPerPage, MaxResults)
}

// ListAuthPolicies returns the authentication policies from the V2
// authn/policies endpoint, which answers with a bare array.
func (c *Client) ListAuthPolicies(ctx context.Context) ([]AuthPolicy, bool, error) {
	return listV2[AuthPolicy](ctx, c, OpListAuthPolicies, "/api/v2/authn/policies", sortByID, maxPerPage, MaxResults)
}

// listInsights reads a System Insights table, up to MaxInsightRows rows.
func listInsights[T any](ctx context.Context, c *Client, op, table string) ([]T, bool, error) {
	return listV2[T](ctx, c, op, "/api/v2/systeminsights/"+table, "", insightsPageSize, MaxInsightRows)
}

func (c *Client) ListBitLockerInfo(ctx context.Context) ([]InsightBitLocker, bool, error) {
	return listInsights[InsightBitLocker](ctx, c, OpListBitLocker, "bitlocker_info")
}

func (c *Client) ListALF(ctx context.Context) ([]InsightALF, bool, error) {
	return listInsights[InsightALF](ctx, c, OpListALF, "alf")
}

func (c *Client) ListWindowsSecurityCenter(ctx context.Context) ([]InsightWindowsSecurityCenter, bool, error) {
	return listInsights[InsightWindowsSecurityCenter](ctx, c, OpListWindowsSecurityCenter, "windows_security_center")
}

func (c *Client) ListWindowsSecurityProducts(ctx context.Context) ([]InsightWindowsSecurityProduct, bool, error) {
	return listInsights[InsightWindowsSecurityProduct](ctx, c, OpListWindowsSecurityProducts, "windows_security_products")
}

func (c *Client) ListInsightUsers(ctx context.Context) ([]InsightUser, bool, error) {
	return listInsights[InsightUser](ctx, c, OpListInsightUsers, "users")
}

// QueryEvents queries Directory Insights events on the insights host. The
// answer is a bare array of at most limit events.
func (c *Client) QueryEvents(ctx context.Context, service string, start, end time.Time, limit int) ([]DirectoryInsightsEvent, error) {
	body := map[string]any{
		"service":    []string{service},
		"start_time": start.UTC().Format(time.RFC3339),
		"end_time":   end.UTC().Format(time.RFC3339),
		"limit":      limit,
	}
	op := componentsdk.Operation{Name: OpQueryEvents, Safe: true, Permission: Permission(OpQueryEvents)}
	var events []DirectoryInsightsEvent
	resp, err := c.do(ctx, op, http.MethodPost, c.insightsURL+"/insights/directory/v1/events", body, &events)
	if err != nil {
		return nil, fmt.Errorf("querying events: %w", err)
	}
	if events == nil {
		return nil, componentsdk.ResponseError(resp, invalidResponse(OpQueryEvents, "is null, not a list"))
	}
	return events, nil
}

// --- HTTP helpers ---

func (c *Client) get(ctx context.Context, op, path string, out any) (*http.Response, error) {
	return c.do(ctx, componentsdk.Operation{Name: op, Permission: Permission(op)}, http.MethodGet, c.consoleURL+path, nil, out)
}

// do sends a request named op and decodes the JSON response into out. It
// returns the response, its body read and closed, so a caller that finds the
// body wanting can build an error with componentsdk.ResponseError. A gap
// recorded from that error names the response's call.
func (c *Client) do(ctx context.Context, op componentsdk.Operation, method, fullURL string, reqBody any, out any) (*http.Response, error) {
	ctx = componentsdk.WithOperation(ctx, op)
	var bodyReader io.Reader
	if reqBody != nil {
		data, err := json.Marshal(reqBody)
		if err != nil {
			return nil, fmt.Errorf("encoding request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.orgID != "" {
		req.Header.Set("x-org-id", c.orgID)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op.Name, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBytes))
		return resp, componentsdk.ResponseError(resp, &APIError{StatusCode: resp.StatusCode, Header: resp.Header})
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return resp, componentsdk.ResponseError(resp, fmt.Errorf("%s: reading the response: %w", op.Name, err))
	}
	if len(data) > maxResponseBytes {
		return resp, componentsdk.ResponseError(resp, componentsdk.CodeError(componentsdk.CodeTooLarge,
			fmt.Errorf("%s: the response is larger than %d bytes", op.Name, maxResponseBytes)))
	}
	if err := json.Unmarshal(data, out); err != nil {
		return resp, componentsdk.ResponseError(resp, fmt.Errorf("%s: decoding the response: %w", op.Name, err))
	}
	return resp, nil
}

func invalidResponse(op, problem string) error {
	return componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf("%s: the response %s", op, problem))
}

// SetConsoleURL overrides the console base URL, for tests.
func (c *Client) SetConsoleURL(u string) {
	c.consoleURL = strings.TrimRight(u, "/")
}

// SetInsightsURL overrides the insights base URL, for tests.
func (c *Client) SetInsightsURL(u string) {
	c.insightsURL = strings.TrimRight(u, "/")
}
