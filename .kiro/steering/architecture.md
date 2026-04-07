# Architecture: Modular Config & GitOps

## Why Directory-Based Config

Abaris uses a directory-based configuration layout (`/config/`) instead of a single monolithic file. This design is intentional and optimised for GitOps workflows:

- **Per-team policy ownership** — each team manages their own `policies/<team>.yaml` file. A developer team's policy file never touches the routing or identity configuration owned by platform engineers.
- **PR-based policy changes** — policy files live in version control. Adding or modifying a group's permissions is a pull request, not a UI click. This gives you a full audit trail, code review, and rollback for every policy change.
- **Separation of concerns** — identity provider configuration (long-lived, security-sensitive) is separated from routing (infrastructure-owned) and policies (team-owned). Different teams can own different files without merge conflicts.
- **GitOps sync** — in a GitOps setup, a separate `policies/` repository can be synced into the running container's `/config/policies/` directory by a sidecar or volume mount. Abaris picks up the changes automatically via hot reload, with no restart required.

## The Three-File Split

| File | Owner | Change frequency | Requires restart? |
|---|---|---|---|
| `config/identity.yaml` | Platform / Security | Rare | Yes |
| `config/routing.yaml` | Platform / Infra | Occasional | Yes |
| `config/policies/*.yaml` | Individual teams | Frequent | No (hot reload) |

**`config/identity.yaml`** owns the `identity_providers` section. It defines which OIDC or SAML providers Abaris trusts. Changes here affect the security boundary of the entire system and require a deliberate restart.

**`config/routing.yaml`** owns the `routes` table (prefix → backend URI) and the `assertion` section (KMS key, issuer, TTL). Routes define the topology of the backend MCP server fleet. The assertion config controls how Identity Assertion Tokens are minted. Both are infrastructure concerns that require a restart to change safely.

**`config/policies/*.yaml`** — one file per group or policy set. Each file contributes one or more `PolicyEntry` items. These are the only files that support hot reload.

## Deep Merge Semantics

When multiple policy files define a `PolicyEntry` for the same group name, Abaris **unions** their `allowed_tools` and `denied_tools` lists rather than replacing them. This is the correct default because:

- Teams may split a group's permissions across multiple files for readability (e.g., `developers-github.yaml` and `developers-jira.yaml`).
- Union semantics mean adding a new file can only expand permissions, never silently remove them. Removing permissions requires explicitly deleting patterns from existing files.
- Replace semantics would make file ordering significant and create subtle bugs when two teams both define entries for a shared group like `read-only`.

Deduplication is applied after union so the resulting `allowed_tools` and `denied_tools` slices contain no repeated patterns.

## Hot Reload Scope

Hot reload applies **only** to the `policies/` directory. `identity.yaml` and `routing.yaml` are loaded once at startup and treated as immutable for the lifetime of the process.

This boundary is a deliberate security decision:

- Identity provider configuration controls which external systems Abaris trusts to issue credentials. Allowing this to change at runtime without a restart would make it possible to silently add a new trusted IdP without a deployment event — a significant security risk.
- Route configuration controls which backend servers receive traffic. Changing routes at runtime could redirect tool calls to unintended backends mid-flight.
- Policy changes, by contrast, are the normal operational activity. Teams add new tools, adjust group permissions, and onboard new groups regularly. Requiring a restart for every policy change would create operational friction and encourage batching changes, which increases risk.

## Cross-File Validation

After every load (startup or hot reload), `config.Loader` runs `validatePolicyRoutes`: it checks that every route prefix referenced in any policy pattern exists as a `prefix` in `routing.yaml`.

This is a safety net for the GitOps workflow. Without it, a team could merge a policy file referencing `jira/*` before the platform team has added the `jira` route to `routing.yaml`. The cross-file validation catches this at load time (fatal at startup, WARN + rollback on hot reload) rather than at request time.

On hot reload, if validation fails, the previous policies remain active and Abaris logs a WARN identifying the offending file, group name, and undefined prefix. The system continues serving traffic with the last known-good policy set.

## GitOps Workflow Mapping

A typical GitOps setup for Abaris policy management:

1. Policy files live in a dedicated `abaris-policies` Git repository (separate from the Abaris application repo).
2. A CI pipeline validates policy files on every PR: runs `abaris dryrun` against representative identities and tool calls to catch regressions before merge.
3. On merge to `main`, a GitOps operator (e.g., Flux, ArgoCD, or a simple sync sidecar) copies the updated `*.yaml` files into the container's `/config/policies/` directory via a shared volume or ConfigMap mount.
4. `fsnotify` detects the file change, `config.Loader` re-merges and re-validates, and the new policies are atomically swapped in — no restart, no dropped requests.
5. If the new policies fail cross-file validation, the operator's sync is effectively a no-op from Abaris's perspective: the previous policies remain active and the WARN log triggers an alert.

This workflow gives platform engineers full control over identity and routing configuration (via the application deployment pipeline) while giving individual teams self-service policy management (via the policies repository) with guardrails enforced by Abaris itself.
