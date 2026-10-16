package jumpcloud

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *Client) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client := NewClient("test-api-key", "")
	client.SetConsoleURL(srv.URL)
	client.SetInsightsURL(srv.URL)
	return srv, client
}

func jsonResponse(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestClient_AuthHeaders(t *testing.T) {
	var gotKey, gotContentType string
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		gotContentType = r.Header.Get("Content-Type")
		jsonResponse(w, map[string]any{"totalCount": 0, "results": []any{}})
	})

	_, _, _ = client.ListSystemUsers(context.Background())
	if gotKey != "test-api-key" {
		t.Errorf("x-api-key = %q, want test-api-key", gotKey)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotContentType)
	}
}

func TestClient_OrgIDHeader(t *testing.T) {
	var gotOrgID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOrgID = r.Header.Get("x-org-id")
		jsonResponse(w, map[string]any{"totalCount": 0, "results": []any{}})
	}))
	t.Cleanup(srv.Close)

	client := NewClient("key", "org-123")
	client.SetConsoleURL(srv.URL)

	_, _, _ = client.ListSystemUsers(context.Background())
	if gotOrgID != "org-123" {
		t.Errorf("x-org-id = %q, want org-123", gotOrgID)
	}
}

func TestClient_ListSystemUsers(t *testing.T) {
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, map[string]any{
			"totalCount": 1,
			"results": []map[string]any{
				{"_id": "u1", "username": "alice", "state": "ACTIVATED", "totp_enabled": true},
			},
		})
	})

	users, total, err := client.ListSystemUsers(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("got %d users, want 1", len(users))
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if users[0].Username != "alice" {
		t.Errorf("username = %q, want alice", users[0].Username)
	}
}

func TestClient_ListApplications(t *testing.T) {
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, map[string]any{
			"totalCount": 1,
			"results": []map[string]any{
				{"_id": "app1", "name": "slack", "displayName": "Slack", "sso": map[string]any{"type": "saml"}},
			},
		})
	})

	apps, _, err := client.ListApplications(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(apps) != 1 {
		t.Fatalf("got %d apps, want 1", len(apps))
	}
	if !apps[0].IsSSOEnabled() {
		t.Error("SSO should be enabled (type=saml)")
	}
}

// V2 authn/policies returns a bare array, not a wrapped object
func TestClient_ListAuthPolicies_BareArray(t *testing.T) {
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, []map[string]any{
			{"id": "p1", "name": "MFA Policy", "type": "user_portal"},
		})
	})

	policies, capped, err := client.ListAuthPolicies(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("got %d policies, want 1", len(policies))
	}
	if policies[0].Name != "MFA Policy" {
		t.Errorf("name = %q, want MFA Policy", policies[0].Name)
	}
	if capped {
		t.Error("capped should be false for a single page")
	}
}

// V1 /api/systems returns {totalCount, results} envelope
func TestClient_ListSystems_V1Envelope(t *testing.T) {
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/systems" {
			t.Errorf("path = %q, want /api/systems", r.URL.Path)
		}
		jsonResponse(w, map[string]any{
			"totalCount": 1,
			"results": []map[string]any{
				{"_id": "s1", "hostname": "mac-1", "os": "Mac OS X", "active": true},
			},
		})
	})

	systems, total, err := client.ListSystems(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(systems) != 1 || total != 1 {
		t.Errorf("got %d systems (total=%d), want 1", len(systems), total)
	}
}

func TestClient_ListSystems_EndpointFields(t *testing.T) {
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"totalCount":2,"results":[
			{"_id":"s1","os":"Mac OS X","osFamily":"darwin","version":"15.1","lastContact":"2026-10-16T10:00:00.000Z",
			 "fde":{"active":false,"keyPresent":true},"primarySystemUser":{"id":"u1"}},
			{"_id":"s2","os":"Windows","osVersionDetail":{"version":"10.0.22631"},"lastContact":null,"fde":{}}
		]}`))
	})

	systems, _, err := client.ListSystems(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mac, win := systems[0], systems[1]
	if mac.FDE == nil || mac.FDE.Active == nil || *mac.FDE.Active {
		t.Error("fde.active=false must decode as a known false")
	}
	if win.FDE == nil || win.FDE.Active != nil {
		t.Error("an absent fde.active must stay unknown")
	}
	if mac.OSVersionString() != "15.1" || win.OSVersionString() != "10.0.22631" {
		t.Errorf("os versions = %q, %q", mac.OSVersionString(), win.OSVersionString())
	}
	if mac.PrimarySystemUser == nil || mac.PrimarySystemUser.ID != "u1" || win.LastContact != "" {
		t.Errorf("primary user or null lastContact decoded wrong: %+v %+v", mac.PrimarySystemUser, win.LastContact)
	}
}

func TestClient_ListInsights_PaginatesBareArrays(t *testing.T) {
	var paths []string
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path+"?"+r.URL.RawQuery)
		rows := make([]map[string]any, 0, insightsPageSize)
		n := insightsPageSize
		if r.URL.Query().Get("skip") != "0" {
			n = 2
		}
		for range n {
			rows = append(rows, map[string]any{"system_id": "s1", "collection_time": "2026-10-16 06:00:00 -0400",
				"drive_letter": "C:", "protection_status": nil, "conversion_status": 1})
		}
		jsonResponse(w, rows)
	})

	rows, capped, err := client.ListBitLockerInfo(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rows) != insightsPageSize+2 || capped {
		t.Errorf("rows = %d capped = %v, want %d uncapped", len(rows), capped, insightsPageSize+2)
	}
	if rows[0].ProtectionStatus != nil || rows[0].ConversionStatus == nil || *rows[0].ConversionStatus != 1 {
		t.Error("null columns must decode as unknown, present ones as values")
	}
	want := []string{
		"/api/v2/systeminsights/bitlocker_info?skip=0&limit=1000",
		"/api/v2/systeminsights/bitlocker_info?skip=1000&limit=1000",
	}
	if len(paths) != 2 || paths[0] != want[0] || paths[1] != want[1] {
		t.Errorf("paths = %v, want %v", paths, want)
	}
}

func TestClient_ListInsights_DeniedIsPermissionError(t *testing.T) {
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	_, _, err := client.ListWindowsSecurityProducts(context.Background())
	if !errors.Is(err, ErrPermissionDenied) {
		t.Errorf("err = %v, want ErrPermissionDenied", err)
	}
}

func TestClient_QueryEvents_InsightsHost(t *testing.T) {
	var gotPath string
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		jsonResponse(w, []any{})
	})

	now := time.Now()
	_, _ = client.QueryEvents(context.Background(), "directory", now.Add(-time.Hour), now, 100)
	if gotPath != "/insights/directory/v1/events" {
		t.Errorf("path = %q, want /insights/directory/v1/events", gotPath)
	}
}

func TestClient_GetOrganization_EmptyListWithOrgID(t *testing.T) {
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, map[string]any{"totalCount": 0, "results": []any{}})
	})

	_, err := client.GetOrganization(context.Background(), "tenant-b")
	if err == nil {
		t.Fatal("expected error when org_id is set but no orgs returned")
	}
	var ve *OrgValidationError
	if !errors.As(err, &ve) {
		t.Errorf("expected OrgValidationError, got %T: %v", err, err)
	}
}

func TestClient_GetOrganization_EmptyListNoOrgID(t *testing.T) {
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, map[string]any{"totalCount": 0, "results": []any{}})
	})

	org, err := client.GetOrganization(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if org != nil {
		t.Error("expected nil org for empty list without org_id")
	}
}

func TestClient_ErrorUnauthorized(t *testing.T) {
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Unauthorized"}`))
	})

	_, _, err := client.ListSystemUsers(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T", err)
	}
	if apiErr.StatusCode != 401 {
		t.Errorf("status = %d, want 401", apiErr.StatusCode)
	}
}

func TestClient_RetryOn429(t *testing.T) {
	attempts := 0
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`rate limited`))
			return
		}
		jsonResponse(w, map[string]any{"totalCount": 0, "results": []any{}})
	})
	client.retryDelay = func(int) time.Duration { return time.Millisecond }

	_, _, err := client.ListSystemUsers(context.Background())
	if err != nil {
		t.Fatalf("unexpected error after retries: %v", err)
	}
	if attempts != 3 {
		t.Errorf("attempts = %d, want 3", attempts)
	}
}

func TestClient_NoRetryOn400(t *testing.T) {
	attempts := 0
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`bad request`))
	})
	client.retryDelay = func(int) time.Duration { return time.Millisecond }

	_, _, err := client.ListSystemUsers(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1 (no retry for 400)", attempts)
	}
}

func TestClient_Pagination(t *testing.T) {
	pages := 0
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		skip := r.URL.Query().Get("skip")
		switch skip {
		case "0", "":
			users := make([]map[string]any, 100)
			for i := range users {
				users[i] = map[string]any{"_id": "u", "username": "user", "state": "ACTIVATED"}
			}
			jsonResponse(w, map[string]any{"totalCount": 150, "results": users})
		default:
			users := make([]map[string]any, 50)
			for i := range users {
				users[i] = map[string]any{"_id": "u", "username": "user", "state": "ACTIVATED"}
			}
			jsonResponse(w, map[string]any{"totalCount": 150, "results": users})
		}
		pages++
	})

	users, total, err := client.ListSystemUsers(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) != 150 {
		t.Errorf("got %d users, want 150", len(users))
	}
	if total != 150 {
		t.Errorf("total = %d, want 150", total)
	}
	if pages != 2 {
		t.Errorf("pages fetched = %d, want 2", pages)
	}
}

func TestClient_ContextCancellation(t *testing.T) {
	_, client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		jsonResponse(w, map[string]any{"totalCount": 0, "results": []any{}})
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := client.ListSystemUsers(ctx)
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
}
