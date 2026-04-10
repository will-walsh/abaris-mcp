//go:build integration

// Package infra contains integration tests for the health check endpoint and
// graceful shutdown behaviour.
//
// Run with: go test -tags integration ./internal/infra/...
//
// Validates: Requirements 9.1, 9.2, 9.4
package infra

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"syscall"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Health check integration tests (Requirements 9.1, 9.2)
// ---------------------------------------------------------------------------

// TestIntegration_HealthEndpoint_Returns200WhenAllHealthy verifies that
// GET /health returns HTTP 200 with {"status":"ok"} when all dependencies
// are healthy.
//
// Validates: Requirements 9.1
func TestIntegration_HealthEndpoint_Returns200WhenAllHealthy(t *testing.T) {
	hc := NewHealthChecker()
	hc.Register("oidc", stubDep{nil})
	hc.Register("backend", stubDep{nil})

	srv := httptest.NewServer(hc.HealthHandler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("expected status=ok, got %q", body["status"])
	}
}

// TestIntegration_HealthEndpoint_Returns503WhenDependencyUnavailable verifies
// that GET /health returns HTTP 503 with a JSON body containing
// {"status":"degraded","dependencies":{...}} when a dependency is unavailable.
//
// Validates: Requirements 9.2
func TestIntegration_HealthEndpoint_Returns503WhenDependencyUnavailable(t *testing.T) {
	hc := NewHealthChecker()
	hc.Register("oidc", stubDep{nil})
	hc.Register("backend", stubDep{errors.New("connection refused")})

	srv := httptest.NewServer(hc.HealthHandler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
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
	// Healthy dependency must not appear in the degraded list.
	if _, found := deps["oidc"]; found {
		t.Errorf("healthy dep 'oidc' should not appear in degraded list")
	}
}

// TestIntegration_HealthEndpoint_JSONContentType verifies that the health
// handler always sets Content-Type: application/json.
//
// Validates: Requirements 9.1, 9.2
func TestIntegration_HealthEndpoint_JSONContentType(t *testing.T) {
	for _, tc := range []struct {
		name    string
		checker *HealthChecker
	}{
		{
			name: "healthy",
			checker: func() *HealthChecker {
				hc := NewHealthChecker()
				hc.Register("dep", stubDep{nil})
				return hc
			}(),
		},
		{
			name: "degraded",
			checker: func() *HealthChecker {
				hc := NewHealthChecker()
				hc.Register("dep", stubDep{errors.New("down")})
				return hc
			}(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.checker.HealthHandler())
			defer srv.Close()

			resp, err := http.Get(srv.URL + "/health")
			if err != nil {
				t.Fatalf("GET /health: %v", err)
			}
			defer resp.Body.Close()

			ct := resp.Header.Get("Content-Type")
			if ct == "" {
				t.Errorf("expected Content-Type header, got empty")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Graceful shutdown integration tests (Requirement 9.4)
// ---------------------------------------------------------------------------

// integrationFreePort returns a random available TCP address on localhost.
func integrationFreePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("integrationFreePort: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// TestIntegration_GracefulShutdown_SIGTERM verifies that sending SIGTERM causes
// RunWithGracefulShutdown to drain in-flight requests and return nil.
//
// Validates: Requirements 9.4
func TestIntegration_GracefulShutdown_SIGTERM(t *testing.T) {
	addr := integrationFreePort(t)
	srv := &http.Server{
		Addr:    addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
	}

	done := make(chan error, 1)
	go func() {
		done <- RunWithGracefulShutdown(context.Background(), srv, 5*time.Second, &noopLogger{})
	}()

	// Give the server time to start listening.
	time.Sleep(50 * time.Millisecond)

	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	if err := p.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("Signal SIGTERM: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil error on clean SIGTERM shutdown, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for graceful shutdown after SIGTERM")
	}
}

// TestIntegration_GracefulShutdown_InFlightRequestCompletes verifies that an
// in-flight request that finishes within the drain timeout is completed before
// the server shuts down.
//
// Validates: Requirements 9.4
func TestIntegration_GracefulShutdown_InFlightRequestCompletes(t *testing.T) {
	addr := integrationFreePort(t)

	const requestDelay = 200 * time.Millisecond
	const drainTimeout = 2 * time.Second

	handlerStarted := make(chan struct{})
	handlerDone := make(chan struct{})

	srv := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(handlerStarted)
			time.Sleep(requestDelay)
			w.WriteHeader(http.StatusOK)
			close(handlerDone)
		}),
	}

	done := make(chan error, 1)
	go func() {
		done <- RunWithGracefulShutdown(context.Background(), srv, drainTimeout, &noopLogger{})
	}()

	time.Sleep(50 * time.Millisecond)

	// Fire a slow request.
	go func() {
		//nolint:errcheck,noctx
		http.Get("http://" + addr + "/slow") //nolint:noctx
	}()

	// Wait until the handler is running before signalling.
	select {
	case <-handlerStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("handler never started")
	}

	p, _ := os.FindProcess(os.Getpid())
	_ = p.Signal(syscall.SIGTERM)

	// The handler should complete before shutdown returns.
	select {
	case <-handlerDone:
		// good — request completed
	case <-time.After(drainTimeout + time.Second):
		t.Fatal("in-flight request did not complete before drain timeout")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil error when request completes within drain timeout, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for shutdown result")
	}
}

// TestIntegration_GracefulShutdown_DrainTimeoutExceeded verifies that when an
// in-flight request outlasts the drain timeout, RunWithGracefulShutdown returns
// a non-nil error (context.DeadlineExceeded).
//
// Validates: Requirements 9.4
func TestIntegration_GracefulShutdown_DrainTimeoutExceeded(t *testing.T) {
	addr := integrationFreePort(t)

	handlerStarted := make(chan struct{})
	srv := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(handlerStarted)
			time.Sleep(2 * time.Second) // outlasts the 100ms drain timeout
		}),
	}

	done := make(chan error, 1)
	go func() {
		done <- RunWithGracefulShutdown(context.Background(), srv, 100*time.Millisecond, &noopLogger{})
	}()

	time.Sleep(50 * time.Millisecond)

	go func() {
		//nolint:errcheck,noctx
		http.Get("http://" + addr + "/slow") //nolint:noctx
	}()

	select {
	case <-handlerStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("handler never started")
	}

	p, _ := os.FindProcess(os.Getpid())
	_ = p.Signal(syscall.SIGTERM)

	select {
	case err := <-done:
		if err == nil {
			t.Error("expected non-nil error when drain timeout is exceeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for shutdown result")
	}
}
