package config_test

import (
	"testing"

	"github.com/will-walsh/abaris-mcp/internal/config"
	"github.com/will-walsh/abaris-mcp/internal/infra"
)

func TestLoader_Load_SampleFiles(t *testing.T) {
	logger := infra.NewSlogLogger()
	loader := config.NewLoader("../../config", logger, nil)

	cfg, err := loader.Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	// identity
	if len(cfg.IdentityProviders) == 0 {
		t.Error("expected at least one identity provider")
	}
	if cfg.IdentityProviders[0].Name != "cognito-oidc" {
		t.Errorf("expected provider name cognito-oidc, got %q", cfg.IdentityProviders[0].Name)
	}

	// routing
	if len(cfg.Routes) == 0 {
		t.Error("expected at least one route")
	}
	if cfg.Routes[0].Prefix != "github" {
		t.Errorf("expected route prefix github, got %q", cfg.Routes[0].Prefix)
	}

	// policies — two files merged
	if len(cfg.Policies) < 2 {
		t.Errorf("expected at least 2 policy groups, got %d", len(cfg.Policies))
	}

	// Data namespace map
	snap := loader.DataSnapshot()
	if _, ok := snap["routing"]; !ok {
		t.Error("expected Data[\"routing\"] to be populated")
	}
	if _, ok := snap["identity"]; !ok {
		t.Error("expected Data[\"identity\"] to be populated")
	}
	if _, ok := snap["policies/developers"]; !ok {
		t.Error("expected Data[\"policies/developers\"] to be populated")
	}
	if _, ok := snap["policies/read-only"]; !ok {
		t.Error("expected Data[\"policies/read-only\"] to be populated")
	}

	t.Logf("loaded %d providers, %d routes, %d policy groups", len(cfg.IdentityProviders), len(cfg.Routes), len(cfg.Policies))
	t.Logf("Data namespaces: %v", keys(snap))
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
