package infra

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// stubDep is a test double for Dependency.
type stubDep struct{ err error }

func (s stubDep) Check(_ context.Context) error { return s.err }

func TestHealthHandler_AllHealthy(t *testing.T) {
	hc := NewHealthChecker()
	hc.Register("oidc", stubDep{nil})
	hc.Register("backend", stubDep{nil})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	hc.HealthHandler()(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("expected status=ok, got %q", body["status"])
	}
}

func TestHealthHandler_OneDegraded(t *testing.T) {
	hc := NewHealthChecker()
	hc.Register("oidc", stubDep{nil})
	hc.Register("backend", stubDep{errors.New("connection refused")})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	hc.HealthHandler()(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}

	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "degraded" {
		t.Errorf("expected status=degraded, got %q", body["status"])
	}

	deps, ok := body["dependencies"].(map[string]any)
	if !ok {
		t.Fatalf("expected dependencies object, got %T", body["dependencies"])
	}
	if _, found := deps["backend"]; !found {
		t.Errorf("expected 'backend' in degraded dependencies, got %v", deps)
	}
	if _, found := deps["oidc"]; found {
		t.Errorf("healthy dep 'oidc' should not appear in degraded list")
	}
}

func TestHealthHandler_MultipleDegraded(t *testing.T) {
	hc := NewHealthChecker()
	hc.Register("oidc", stubDep{errors.New("timeout")})
	hc.Register("backend", stubDep{errors.New("connection refused")})
	hc.Register("kms", stubDep{errors.New("access denied")})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	hc.HealthHandler()(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}

	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}

	deps, ok := body["dependencies"].(map[string]any)
	if !ok {
		t.Fatalf("expected dependencies object")
	}
	for _, name := range []string{"oidc", "backend", "kms"} {
		if _, found := deps[name]; !found {
			t.Errorf("expected %q in degraded dependencies", name)
		}
	}
}

func TestHealthHandler_NoDependencies(t *testing.T) {
	hc := NewHealthChecker()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	hc.HealthHandler()(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with no deps, got %d", rec.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("expected status=ok, got %q", body["status"])
	}
}
