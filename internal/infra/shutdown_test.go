package infra

import (
	"context"
	"net"
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"
)

// noopLogger is a minimal domain.Logger for tests.
type noopLogger struct{}

func (n *noopLogger) Info(msg string, args ...any)  {}
func (n *noopLogger) Warn(msg string, args ...any)  {}
func (n *noopLogger) Error(msg string, args ...any) {}
func (n *noopLogger) Debug(msg string, args ...any) {}

// freePort returns a random available TCP port on localhost.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// TestGracefulShutdown_SIGINT verifies that sending SIGINT causes the server
// to shut down cleanly and RunWithGracefulShutdown returns nil.
func TestGracefulShutdown_SIGINT(t *testing.T) {
	addr := freePort(t)
	srv := &http.Server{
		Addr:    addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
	}

	done := make(chan error, 1)
	go func() {
		done <- RunWithGracefulShutdown(context.Background(), srv, 5*time.Second, &noopLogger{})
	}()

	// Give the server a moment to start listening.
	time.Sleep(50 * time.Millisecond)

	// Send SIGINT to the current process.
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	if err := p.Signal(syscall.SIGINT); err != nil {
		t.Fatalf("Signal: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil error on clean shutdown, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for graceful shutdown")
	}
}

// TestGracefulShutdown_DrainTimeout verifies that when in-flight requests
// outlast the drain timeout, RunWithGracefulShutdown returns a non-nil error.
func TestGracefulShutdown_DrainTimeout(t *testing.T) {
	addr := freePort(t)

	// Handler that blocks longer than the drain timeout.
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

	// Wait for the server to be ready, then fire a slow request.
	time.Sleep(50 * time.Millisecond)
	go func() {
		//nolint:errcheck,noctx
		http.Get("http://" + addr + "/slow") //nolint:noctx
	}()

	// Wait until the handler is actually running before signalling.
	select {
	case <-handlerStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("handler never started")
	}

	// Signal shutdown.
	p, _ := os.FindProcess(os.Getpid())
	_ = p.Signal(syscall.SIGINT)

	select {
	case err := <-done:
		if err == nil {
			t.Error("expected a non-nil error when drain timeout is exceeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for shutdown result")
	}
}
