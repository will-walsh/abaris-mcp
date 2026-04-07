package infra

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
)

// Dependency is a named component that can report its health.
// Implementations may check OIDC provider reachability, backend MCP server
// reachability, or any other required dependency.
type Dependency interface {
	Check(ctx context.Context) error
}

// HealthChecker holds a named list of Dependency checkers and exposes an
// HTTP handler that reports aggregate health.
type HealthChecker struct {
	deps []namedDep
}

type namedDep struct {
	name string
	dep  Dependency
}

// NewHealthChecker creates a HealthChecker with no registered dependencies.
func NewHealthChecker() *HealthChecker {
	return &HealthChecker{}
}

// Register adds a named dependency to the checker.
func (h *HealthChecker) Register(name string, dep Dependency) {
	h.deps = append(h.deps, namedDep{name: name, dep: dep})
}

// HealthHandler returns an http.HandlerFunc that checks all registered
// dependencies concurrently.
//
//   - All healthy  → HTTP 200, {"status":"ok"}
//   - Any degraded → HTTP 503, {"status":"degraded","dependencies":{"<name>":"<error>"}}
func (h *HealthChecker) HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		type result struct {
			name string
			err  error
		}

		results := make([]result, len(h.deps))
		var wg sync.WaitGroup
		wg.Add(len(h.deps))

		for i, nd := range h.deps {
			i, nd := i, nd
			go func() {
				defer wg.Done()
				results[i] = result{name: nd.name, err: nd.dep.Check(ctx)}
			}()
		}
		wg.Wait()

		degraded := make(map[string]string)
		for _, res := range results {
			if res.err != nil {
				degraded[res.name] = res.err.Error()
			}
		}

		w.Header().Set("Content-Type", "application/json")

		if len(degraded) == 0 {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}

		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":       "degraded",
			"dependencies": degraded,
		})
	}
}
