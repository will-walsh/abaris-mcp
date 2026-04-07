package infra

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/will-walsh/abaris-mcp/internal/domain"
)

// RunWithGracefulShutdown starts srv in a background goroutine, then blocks
// until SIGTERM or SIGINT is received (or ctx is cancelled). On signal it
// calls srv.Shutdown with a context bounded by drainTimeout.
//
// The server's ErrorLog is set to write to os.Stdout so that all log output
// goes to stdout, consistent with Requirement 9.3.
//
// Returns nil if shutdown completes within drainTimeout, or the context error
// (context.DeadlineExceeded) if the drain timeout is exceeded.
func RunWithGracefulShutdown(ctx context.Context, srv *http.Server, drainTimeout time.Duration, logger domain.Logger) error {
	// Ensure the server's own error logger writes to stdout (Req 9.3).
	srv.ErrorLog = log.New(os.Stdout, "", log.LstdFlags)

	// Start serving in a goroutine; ignore ErrServerClosed which is expected.
	serveErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
		close(serveErr)
	}()

	// Wait for a signal or context cancellation.
	sigCtx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	select {
	case err := <-serveErr:
		// Server failed to start or crashed before any signal.
		return err
	case <-sigCtx.Done():
		// Signal received (or parent ctx cancelled).
	}

	logger.Info("received shutdown signal, draining in-flight requests")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), drainTimeout)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("drain timeout exceeded, forcing shutdown")
		return err
	}

	logger.Info("shutdown complete")
	return nil
}
