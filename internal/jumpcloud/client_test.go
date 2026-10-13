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

	policies, err := client.ListAuthPolicies(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("got %d policies, want 1", len(policies))
	}
	if policies[0].Name != "MFA Policy" {
		t.Errorf("name = %q, want MFA Policy", policies[0].Name)
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
