package jumpcloud

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// consoleBaseURL is the base for V1/V2 management APIs.
	consoleBaseURL = "https://console.jumpcloud.com"
	// insightsBaseURL is the base for the Directory Insights API.
	insightsBaseURL = "https://api.jumpcloud.com"

	requestTimeout = 30 * time.Second
	maxPerPage     = 100
	maxResults     = 50000
)

var (
	ErrUnauthorized     = fmt.Errorf("unauthorized")
	ErrPermissionDenied = fmt.Errorf("permission denied")
	ErrNotFound         = fmt.Errorf("not found")
)

type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("jumpcloud API error: status %d: %s", e.StatusCode, e.Body)
}

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

type retryableError struct {
	statusCode int
	msg        string
}

func (e *retryableError) Error() string { return e.msg }

// Client is a JumpCloud REST API client supporting V1, V2, and Directory
// Insights endpoints. It enforces same-origin redirects so the API key is
// never forwarded to a different host.
type Client struct {
	consoleURL  string
	insightsURL string
	apiKey      string
	orgID       string
	httpClient  *http.Client
	retryDelay  func(attempt int) time.Duration
}

// NewClient creates a JumpCloud API client. orgID is optional and used for
// MSP/multi-tenant scenarios via the x-org-id header.
func NewClient(apiKey, orgID string) *Client {
	consoleOrigin, _ := url.Parse(consoleBaseURL)
	insightsOrigin, _ := url.Parse(insightsBaseURL)

	return &Client{
		consoleURL:  consoleBaseURL,
		insightsURL: insightsBaseURL,
		apiKey:      apiKey,
		orgID:       orgID,
		httpClient: &http.Client{
			Timeout:       requestTimeout,
			CheckRedirect: sameOriginRedirect(consoleOrigin, insightsOrigin),
		},
		retryDelay: backoff,
	}
}

// sameOriginRedirect rejects redirects to hosts outside the two known JumpCloud
// API origins. This prevents the x-api-key header from leaking.
func sameOriginRedirect(origins ...*url.URL) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("too many redirects")
		}
		if req.URL.Scheme == "http" {
			return fmt.Errorf("refusing HTTPS-to-HTTP downgrade redirect to %s", req.URL.Host)
		}
		for _, origin := range origins {
			if strings.EqualFold(req.URL.Host, origin.Host) {
				return nil
			}
		}
		return fmt.Errorf("refusing cross-origin redirect to %s", req.URL.Host)
	}
}

// ListSystemUsers returns all system users via the V1 API.
// Returns the fetched users, the server-reported total, and any error.
// When the fetched count is less than the server total, the caller should
// treat results as partial.
func (c *Client) ListSystemUsers(ctx context.Context) ([]SystemUser, int, error) {
	var all []SystemUser
	serverTotal := 0
	skip := 0
	for {
		var page struct {
			TotalCount int          `json:"totalCount"`
			Results    []SystemUser `json:"results"`
		}
		path := fmt.Sprintf("/api/systemusers?skip=%d&limit=%d", skip, maxPerPage)
		if err := c.consoleGet(ctx, path, &page); err != nil {
			return nil, 0, fmt.Errorf("listing system users: %w", err)
		}
		serverTotal = page.TotalCount
		all = append(all, page.Results...)
		if len(all) >= page.TotalCount || len(page.Results) < maxPerPage || len(all) >= maxResults {
			break
		}
		skip = len(all)
	}
	return all, serverTotal, nil
}

// ListApplications returns all SSO applications via the V1 API.
func (c *Client) ListApplications(ctx context.Context) ([]Application, int, error) {
	var all []Application
	serverTotal := 0
	skip := 0
	for {
		var page struct {
			TotalCount int           `json:"totalCount"`
			Results    []Application `json:"results"`
		}
		path := fmt.Sprintf("/api/applications?skip=%d&limit=%d", skip, maxPerPage)
		if err := c.consoleGet(ctx, path, &page); err != nil {
			return nil, 0, fmt.Errorf("listing applications: %w", err)
		}
		serverTotal = page.TotalCount
		all = append(all, page.Results...)
		if len(all) >= page.TotalCount || len(page.Results) < maxPerPage || len(all) >= maxResults {
			break
		}
		skip = len(all)
	}
	return all, serverTotal, nil
}

// GetOrganization resolves the organization identity. When orgID is provided
// (MSP scenario), it validates that the ID matches a returned organization.
// When orgID is empty, returns the sole organization or an error if multiple
// are present (ambiguous without explicit selection). All pages are fetched
// so that validation is not limited to the first page.
func (c *Client) GetOrganization(ctx context.Context, orgID string) (*Organization, error) {
	var all []Organization
	skip := 0
	for {
		var page struct {
			TotalCount int            `json:"totalCount"`
			Results    []Organization `json:"results"`
		}
		path := fmt.Sprintf("/api/organizations?skip=%d&limit=%d", skip, maxPerPage)
		if err := c.consoleGet(ctx, path, &page); err != nil {
			return nil, fmt.Errorf("getting organizations: %w", err)
		}
		all = append(all, page.Results...)
		if len(all) >= page.TotalCount || len(page.Results) < maxPerPage {
			break
		}
		skip = len(all)
	}

	if len(all) == 0 {
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

// OrgValidationError indicates that organization identity could not be
// resolved. This is a configuration error, not a transient failure.
type OrgValidationError struct {
	msg string
}

func (e *OrgValidationError) Error() string { return e.msg }

// ListAdministrators returns all JumpCloud admin portal administrators.
func (c *Client) ListAdministrators(ctx context.Context) ([]Administrator, int, error) {
	var all []Administrator
	serverTotal := 0
	skip := 0
	for {
		var page struct {
			TotalCount int             `json:"totalCount"`
			Results    []Administrator `json:"results"`
		}
		path := fmt.Sprintf("/api/administrators?skip=%d&limit=%d", skip, maxPerPage)
		if err := c.consoleGet(ctx, path, &page); err != nil {
			return nil, 0, fmt.Errorf("listing administrators: %w", err)
		}
		serverTotal = page.TotalCount
		all = append(all, page.Results...)
		if len(all) >= page.TotalCount || len(page.Results) < maxPerPage || len(all) >= maxResults {
			break
		}
		skip = len(all)
	}
	return all, serverTotal, nil
}

// ListSystems returns all managed systems via the V1 API.
func (c *Client) ListSystems(ctx context.Context) ([]System, int, error) {
	var all []System
	serverTotal := 0
	skip := 0
	for {
		var page struct {
			TotalCount int      `json:"totalCount"`
			Results    []System `json:"results"`
		}
		path := fmt.Sprintf("/api/systems?skip=%d&limit=%d", skip, maxPerPage)
		if err := c.consoleGet(ctx, path, &page); err != nil {
			return nil, 0, fmt.Errorf("listing systems: %w", err)
		}
		serverTotal = page.TotalCount
		all = append(all, page.Results...)
		if len(all) >= page.TotalCount || len(page.Results) < maxPerPage || len(all) >= maxResults {
			break
		}
		skip = len(all)
	}
	return all, serverTotal, nil
}

// ListUserGroups returns all user groups via the V2 API.
// The capped return value is true when the result was truncated at the
// internal safety cap and may not represent all groups.
func (c *Client) ListUserGroups(ctx context.Context) ([]UserGroup, bool, error) {
	var all []UserGroup
	skip := 0
	for {
		var page []UserGroup
		path := fmt.Sprintf("/api/v2/usergroups?skip=%d&limit=%d", skip, maxPerPage)
		if err := c.consoleGet(ctx, path, &page); err != nil {
			return nil, false, fmt.Errorf("listing user groups: %w", err)
		}
		all = append(all, page...)
		if len(page) < maxPerPage {
			return all, false, nil
		}
		if len(all) >= maxResults {
			return all, true, nil
		}
		skip = len(all)
	}
}

// ListSystemGroups returns all system groups via the V2 API.
func (c *Client) ListSystemGroups(ctx context.Context) ([]SystemGroup, bool, error) {
	var all []SystemGroup
	skip := 0
	for {
		var page []SystemGroup
		path := fmt.Sprintf("/api/v2/systemgroups?skip=%d&limit=%d", skip, maxPerPage)
		if err := c.consoleGet(ctx, path, &page); err != nil {
			return nil, false, fmt.Errorf("listing system groups: %w", err)
		}
		all = append(all, page...)
		if len(page) < maxPerPage {
			return all, false, nil
		}
		if len(all) >= maxResults {
			return all, true, nil
		}
		skip = len(all)
	}
}

// ListAuthPolicies returns all authentication policies via the V2 API.
// The V2 authn/policies endpoint returns a bare array (not a wrapped object).
func (c *Client) ListAuthPolicies(ctx context.Context) ([]AuthPolicy, bool, error) {
	var all []AuthPolicy
	skip := 0
	for {
		var page []AuthPolicy
		path := fmt.Sprintf("/api/v2/authn/policies?skip=%d&limit=%d", skip, maxPerPage)
		if err := c.consoleGet(ctx, path, &page); err != nil {
			return nil, false, fmt.Errorf("listing auth policies: %w", err)
		}
		all = append(all, page...)
		if len(page) < maxPerPage {
			return all, false, nil
		}
		if len(all) >= maxResults {
			return all, true, nil
		}
		skip = len(all)
	}
}

// QueryEvents queries Directory Insights events. Uses the dedicated insights
// API host (api.jumpcloud.com), not the console host.
func (c *Client) QueryEvents(ctx context.Context, service string, start, end time.Time, limit int) ([]DirectoryInsightsEvent, error) {
	body := map[string]any{
		"service":    []string{service},
		"start_time": start.UTC().Format(time.RFC3339),
		"end_time":   end.UTC().Format(time.RFC3339),
		"limit":      limit,
	}
	var events []DirectoryInsightsEvent
	if err := c.insightsPost(ctx, "/insights/directory/v1/events", body, &events); err != nil {
		return nil, fmt.Errorf("querying events: %w", err)
	}
	return events, nil
}

// --- HTTP helpers ---

func (c *Client) consoleGet(ctx context.Context, path string, out any) error {
	return c.doWithRetry(ctx, http.MethodGet, c.consoleURL+path, nil, out)
}

func (c *Client) insightsPost(ctx context.Context, path string, body any, out any) error {
	return c.doWithRetry(ctx, http.MethodPost, c.insightsURL+path, body, out)
}

func (c *Client) doWithRetry(ctx context.Context, method, fullURL string, body any, out any) error {
	var lastErr error
	for attempt := range maxAttempts {
		err := c.do(ctx, method, fullURL, body, out)
		if err == nil {
			return nil
		}

		if !isRetryableErr(err) {
			return err
		}

		lastErr = err
		if sleepErr := sleep(ctx, c.retryDelay(attempt)); sleepErr != nil {
			return sleepErr
		}
	}
	return &APIError{
		StatusCode: retryStatusCode(lastErr),
		Body:       "max retries exceeded",
	}
}

func (c *Client) do(ctx context.Context, method, fullURL string, reqBody any, out any) error {
	var bodyReader io.Reader
	if reqBody != nil {
		data, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("encoding request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.orgID != "" {
		req.Header.Set("x-org-id", c.orgID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		if isRetryable(resp.StatusCode) {
			return &retryableError{
				statusCode: resp.StatusCode,
				msg:        fmt.Sprintf("HTTP %d", resp.StatusCode),
			}
		}
		return &APIError{StatusCode: resp.StatusCode, Body: truncateBody(respBody)}
	}

	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func isRetryableErr(err error) bool {
	var re *retryableError
	return errors.As(err, &re)
}

func retryStatusCode(err error) int {
	var re *retryableError
	if errors.As(err, &re) {
		return re.statusCode
	}
	return 0
}

func truncateBody(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}

// SetConsoleURL overrides the console base URL (for testing).
func (c *Client) SetConsoleURL(u string) {
	c.consoleURL = strings.TrimRight(u, "/")
}

// SetInsightsURL overrides the insights base URL (for testing).
func (c *Client) SetInsightsURL(u string) {
	c.insightsURL = strings.TrimRight(u, "/")
}
