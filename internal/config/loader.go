// Package config loads and watches the /config/ directory.
//
// # Namespace model
//
// Every YAML file's stem becomes a namespace key in Loader.Data, mirroring
// OPA's data document model:
//
//	config/identity.yaml        → Data["identity"]
//	config/routing.yaml         → Data["routing"]
//	config/policies/developers.yaml → Data["policies/developers"]
//
// This means a future OPA migration is a lift-and-shift: Rego policies that
// reference data.routing or data.policies.developers will work without changes
// to the underlying YAML files.
//
// # Typed access
//
// Alongside the raw Data map, Loader.Load() returns a fully-typed domain.Config
// so the rest of the codebase never has to do map assertions.
//
// # Hot reload
//
// Loader.Watch() uses fsnotify to watch config/policies/. When any *.yaml file
// changes, the policies are re-merged and re-validated. On success the active
// policy slice is atomically swapped. On failure the previous policies are
// retained and a WARN is logged.
//
// identity.yaml and routing.yaml are immutable at runtime — changes require a
// process restart (deliberate security boundary).
package config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/go-playground/validator/v10"
	"github.com/will-walsh/abaris-mcp/internal/domain"
	"gopkg.in/yaml.v3"
)

var validate = validator.New()

// Loader loads and watches the /config/ directory.
type Loader struct {
	configDir string
	logger    domain.Logger

	mu       sync.RWMutex
	current  domain.Config
	onChange func(domain.Config) // called after a successful hot-reload

	// Data mirrors OPA's data document model.
	// Key = filename stem (e.g. "routing", "policies/developers").
	// Value = raw map[string]any parsed from the YAML file.
	// Access is protected by mu.
	Data map[string]any
}

// NewLoader creates a Loader for the given config directory.
// onChange is called (in a goroutine) whenever a hot-reload succeeds.
// Pass nil if you don't need the callback.
func NewLoader(configDir string, logger domain.Logger, onChange func(domain.Config)) *Loader {
	return &Loader{
		configDir: configDir,
		logger:    logger,
		onChange:  onChange,
		Data:      make(map[string]any),
	}
}

// Load performs the initial configuration load:
//  1. Reads and validates identity.yaml → IdentityConfig
//  2. Reads and validates routing.yaml  → RoutingConfig
//  3. Globs all *.yaml in policies/     → []PolicyFileConfig
//  4. Deep-merges policies
//  5. Validates that every policy prefix exists in routing.yaml
//  6. Populates Loader.Data with namespace-keyed raw maps
//  7. Returns the merged domain.Config
func (l *Loader) Load() (domain.Config, error) {
	// 1. identity.yaml
	identityCfg, identityRaw, err := loadFile[domain.IdentityConfig](
		filepath.Join(l.configDir, "identity.yaml"),
	)
	if err != nil {
		return domain.Config{}, fmt.Errorf("identity.yaml: %w", err)
	}

	// 2. routing.yaml
	routingCfg, routingRaw, err := loadFile[domain.RoutingConfig](
		filepath.Join(l.configDir, "routing.yaml"),
	)
	if err != nil {
		return domain.Config{}, fmt.Errorf("routing.yaml: %w", err)
	}

	// 3. policies/*.yaml
	policyFiles, policyRaws, err := l.loadPolicyFiles()
	if err != nil {
		return domain.Config{}, err
	}

	// 4. deep-merge
	merged := deepMergePolicies(policyFiles)

	// 5. cross-file validation
	if err := validatePolicyRoutes(merged, routingCfg.Routes); err != nil {
		return domain.Config{}, err
	}

	cfg := domain.Config{
		IdentityProviders:  identityCfg.IdentityProviders,
		SecondaryProviders: identityCfg.SecondaryProviders,
		TokenStore:         identityCfg.TokenStore,
		Routes:             routingCfg.Routes,
		Assertion:          routingCfg.Assertion,
		Policies:           merged,
	}

	if err := validateSecondaryProviders(cfg.SecondaryProviders); err != nil {
		return domain.Config{}, err
	}

	// 6. populate Data map under write lock
	l.mu.Lock()
	l.current = cfg
	l.Data["identity"] = identityRaw
	l.Data["routing"] = routingRaw
	for ns, raw := range policyRaws {
		l.Data[ns] = raw
	}
	l.mu.Unlock()

	return cfg, nil
}

// Watch starts an fsnotify watcher on the policies/ subdirectory.
// It blocks until ctx is cancelled or the watcher encounters a fatal error.
// Call this in a goroutine after Load().
func (l *Loader) Watch(stopCh <-chan struct{}) error {
	policiesDir := filepath.Join(l.configDir, "policies")

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("config watcher: %w", err)
	}
	defer watcher.Close()

	if err := watcher.Add(policiesDir); err != nil {
		return fmt.Errorf("config watcher: add %s: %w", policiesDir, err)
	}

	l.logger.Info("config watcher started", "dir", policiesDir)

	for {
		select {
		case <-stopCh:
			l.logger.Info("config watcher stopped")
			return nil

		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if !isYAML(event.Name) {
				continue
			}
			if event.Has(fsnotify.Create) || event.Has(fsnotify.Write) || event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) {
				l.logger.Info("policy file changed, reloading", "file", event.Name, "op", event.Op.String())
				l.reloadPolicies()
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			l.logger.Error("config watcher error", "err", err)
		}
	}
}

// reloadPolicies re-reads all policy files, deep-merges, validates, and
// atomically swaps the active policies on success. On failure it logs a WARN
// and retains the previous policies unchanged.
func (l *Loader) reloadPolicies() {
	policyFiles, policyRaws, err := l.loadPolicyFiles()
	if err != nil {
		l.logger.Warn("hot-reload failed: could not read policy files, retaining previous policies", "err", err)
		return
	}

	merged := deepMergePolicies(policyFiles)

	l.mu.RLock()
	routes := l.current.Routes
	l.mu.RUnlock()

	if err := validatePolicyRoutes(merged, routes); err != nil {
		l.logger.Warn("hot-reload rejected: cross-file validation failed, retaining previous policies", "err", err)
		return
	}

	l.mu.Lock()
	l.current.Policies = merged
	for ns, raw := range policyRaws {
		l.Data[ns] = raw
	}
	newCfg := l.current
	l.mu.Unlock()

	l.logger.Info("hot-reload succeeded", "policy_groups", len(merged))

	if l.onChange != nil {
		go l.onChange(newCfg)
	}
}

// Current returns a snapshot of the active configuration under a read lock.
func (l *Loader) Current() domain.Config {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.current
}

// DataSnapshot returns a copy of the namespace-keyed raw data map.
// Mirrors OPA's data document: Data["routing"] == data.routing in Rego.
func (l *Loader) DataSnapshot() map[string]any {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make(map[string]any, len(l.Data))
	for k, v := range l.Data {
		out[k] = v
	}
	return out
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// loadFile reads, parses, and validates a single YAML file into T.
// Returns both the typed struct and the raw map[string]any for the Data namespace.
func loadFile[T any](path string) (T, map[string]any, error) {
	var zero T
	data, err := os.ReadFile(path)
	if err != nil {
		return zero, nil, fmt.Errorf("read: %w", err)
	}

	var typed T
	if err := yaml.Unmarshal(data, &typed); err != nil {
		return zero, nil, fmt.Errorf("parse: %w", err)
	}
	if err := validate.Struct(&typed); err != nil {
		return zero, nil, fmt.Errorf("validate: %w", err)
	}

	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return zero, nil, fmt.Errorf("parse raw: %w", err)
	}

	return typed, raw, nil
}

// loadPolicyFiles globs all *.yaml files in config/policies/, parses each one,
// and returns the typed slice and the namespace-keyed raw maps.
func (l *Loader) loadPolicyFiles() ([]domain.PolicyFileConfig, map[string]any, error) {
	pattern := filepath.Join(l.configDir, "policies", "*.yaml")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, nil, fmt.Errorf("glob policies: %w", err)
	}

	var files []domain.PolicyFileConfig
	raws := make(map[string]any, len(matches))

	for _, match := range matches {
		typed, raw, err := loadFile[domain.PolicyFileConfig](match)
		if err != nil {
			return nil, nil, fmt.Errorf("policy file %s: %w", match, err)
		}
		files = append(files, typed)

		// namespace key: "policies/<stem>" e.g. "policies/developers"
		stem := strings.TrimSuffix(filepath.Base(match), filepath.Ext(match))
		raws["policies/"+stem] = raw
	}

	return files, raws, nil
}

// deepMergePolicies merges PolicyEntry slices from multiple files.
// For duplicate group names, allowed_tools and denied_tools are unioned
// (deduplicated). The result is stable-sorted by group name.
func deepMergePolicies(files []domain.PolicyFileConfig) []domain.PolicyEntry {
	merged := make(map[string]*domain.PolicyEntry)

	for _, f := range files {
		for _, p := range f.Policies {
			if existing, ok := merged[p.Group]; ok {
				existing.ReducedScope.AllowedTools = union(existing.ReducedScope.AllowedTools, p.ReducedScope.AllowedTools)
				existing.ReducedScope.DeniedTools = union(existing.ReducedScope.DeniedTools, p.ReducedScope.DeniedTools)
			} else {
				entry := p
				merged[p.Group] = &entry
			}
		}
	}

	result := make([]domain.PolicyEntry, 0, len(merged))
	for _, e := range merged {
		result = append(result, *e)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Group < result[j].Group
	})
	return result
}

// validatePolicyRoutes checks that every route prefix referenced in any policy
// pattern exists as a Prefix in routes. Returns a descriptive error on failure.
func validatePolicyRoutes(policies []domain.PolicyEntry, routes []domain.RouteEntry) error {
	prefixSet := make(map[string]struct{}, len(routes))
	for _, r := range routes {
		prefixSet[r.Prefix] = struct{}{}
	}

	for _, p := range policies {
		allPatterns := append(p.ReducedScope.AllowedTools, p.ReducedScope.DeniedTools...)
		for _, pattern := range allPatterns {
			prefix := toolPrefix(pattern)
			if _, ok := prefixSet[prefix]; !ok {
				return fmt.Errorf(
					"policy group %q references undefined route prefix %q (pattern: %q) — add it to routing.yaml",
					p.Group, prefix, pattern,
				)
			}
		}
	}
	return nil
}

// toolPrefix returns the segment before the first "/" in a tool name or pattern.
func toolPrefix(s string) string {
	if i := strings.Index(s, "/"); i >= 0 {
		return s[:i]
	}
	return s
}

// union returns a deduplicated, stable-sorted union of two string slices.
func union(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	for _, s := range a {
		seen[s] = struct{}{}
	}
	for _, s := range b {
		seen[s] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// isYAML reports whether the file path has a .yaml or .yml extension.
func isYAML(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".yaml" || ext == ".yml"
}

// SecretsResolver retrieves a secret value by ARN.
// The production implementation wraps infra.SecretsManagerAdapter.
type SecretsResolver interface {
	GetIDPClientSecret(ctx context.Context, secretARN string) (string, error)
}

// ResolveSecondaryProviderSecrets resolves the client_secret for each secondary
// provider from Secrets Manager and stores it in the Config.
// Call this after Load() at startup. Returns an error if any secret is missing.
func (l *Loader) ResolveSecondaryProviderSecrets(ctx context.Context, resolver SecretsResolver) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := range l.current.SecondaryProviders {
		p := &l.current.SecondaryProviders[i]
		secret, err := resolver.GetIDPClientSecret(ctx, p.ClientSecretARN)
		if err != nil {
			return fmt.Errorf("secondary_providers[%s]: resolve client_secret_arn: %w", p.Name, err)
		}
		p.ClientSecret = secret
	}
	return nil
}

// validateSecondaryProviders checks that all secondary provider names are unique.
func validateSecondaryProviders(providers []domain.SecondaryProviderConfig) error {
	seen := make(map[string]struct{}, len(providers))
	for _, p := range providers {
		if _, dup := seen[p.Name]; dup {
			return fmt.Errorf("secondary_providers: duplicate provider name %q", p.Name)
		}
		seen[p.Name] = struct{}{}
	}
	return nil
}
