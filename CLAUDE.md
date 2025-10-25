# CLAUDE.md

AI maintainer context for lazy-beanstalk codebase. For user-facing docs, see @README.md.

## Project Overview

Lazy Beanstalk is a pip-installable Python package that simplifies AWS Elastic Beanstalk deployments.

**Version**: 2.0.0

**Key Architecture**: Pip package with CLI + Python API, smart defaults, stateful deployments via EB CLI-compatible config.

## Package Structure

```
lazy-beanstalk/
├── lazy_beanstalk/          # Main package
│   ├── config.py            # Config, state, AWS client management
│   ├── ship.py              # Deployment orchestration
│   ├── secure.py            # HTTPS + auto-OIDC
│   ├── shield.py            # Standalone OIDC
│   ├── scrap.py             # Resource cleanup
│   ├── support.py           # Shared AWS utilities
│   ├── cli.py               # Click CLI wrapper
│   └── defaults/policies/   # Default trust policies (eb, ec2)
├── tests/                   # Pytest suite
├── app/                     # Demo app (terminaide chatline)
└── pyproject.toml
```

## Core Modules

### config.py
Central configuration, state management, AWS client caching.

**Key Classes**:
- `ClientManager`: Singleton AWS client cache with region management
- `StateManager`: Manages `.elasticbeanstalk/config.yml` (EB CLI compatible YAML format)

**Key Functions**:
- `merge_config(**kwargs)`: Implements 5-layer config hierarchy
- `detect_changes(current, state)`: Determines if environment update needed
- `get_env_var(name, fallback, default, required)`: Hybrid env var resolution
- `get_oidc_env_var(name, required)`: OIDC-specific with unprefixed fallback

**Config Hierarchy** (low → high priority):
1. Hardcoded defaults (see @README.md)
2. **Environment variables** (`.env` auto-loaded via python-dotenv)
3. EB CLI config (`.elasticbeanstalk/config.yml` global section)
4. lazy_beanstalk state (`.elasticbeanstalk/config.yml` lazy_beanstalk section)
5. API parameters / CLI flags

**Environment Variable Design**:
- Hybrid naming: `LB_*` canonical with standard fallbacks
- Examples: `LB_REGION` → `AWS_REGION` → `AWS_DEFAULT_REGION`
- OIDC provider creds: `LB_OIDC_CLIENT_ID` → `OIDC_CLIENT_ID` (reusable)
- ALB-specific: `LB_OIDC_SESSION_TIMEOUT` (no fallback)

**Auto-Loading Pattern**:
- All `.env*` files loaded and passed to EB
- EXCEPT `.env.lb` (deployment config only, never passed to EB)
- Use `--deployment-env` flag to specify alternative exclusion file
- `load_app_env_vars()` handles filtering logic
- All `.env*` files excluded from bundle (never uploaded)

### ship.py
Deployment orchestration with change detection.

**Flow**: Load state → merge config → validate → detect changes → create/update IAM → bundle app → upload S3 → create/update environment → save state

**Key Implementation Details**:
- Bundle creation: Uses `.ebignore` (fallback `.gitignore`), excludes `.git` by default, filters dirs before descent in `os.walk()`
- Change detection: Compares current vs previous state to determine update vs no-op
- HTTPS preservation: Captures HTTPS config before update, restores after
- Spot instances: 1:1 sync (always sets `EnableSpot` option)

**Immutable Settings** (warn but continue):
- Platform/solution stack (requires recreation)
- Load balancer type (requires recreation)
- Tags (only settable at creation time)

### secure.py
HTTPS via ACM + Route 53. **Auto-configures OIDC** if env vars present.

**Flow**: Load state → pick cert → validate domains → setup HTTPS listener → HTTP→HTTPS redirect → create DNS records → **check for OIDC env vars** → auto-call `shield()` if present

**Domain Modes** (see @README.md for user docs):
- `sub`: `{app-name}.example.com`
- `root`: `example.com`
- `custom`: Multiple from `LB_CUSTOM_SUBDOMAINS` comma-separated

**Auto-OIDC Logic** (lines 551-570):
- After HTTPS completes, checks `get_oidc_env_var("CLIENT_ID")` or `get_oidc_env_var("ISSUER")`
- If present: calls `shield()`, returns combined result with `oidc` key
- If fails: logs warning, suggests manual `lb shield`
- If not present: logs hint to add OIDC vars

### shield.py
Standalone OIDC authentication on ALB. Can also be auto-invoked by `secure()`.

**Flow**: Load state → read OIDC env vars → validate params → find HTTPS listener (requires `secure` first) → clear existing rules → set default 503 → create auth rule for `/*`

**Interactive Fallback**: Prompts for `client_secret` via `getpass` if not in env vars (lines 224-225)

**Required Params**: All 6 OIDC endpoints must be provided (validated in `validate_oidc_params()`)

### scrap.py
Resource cleanup with safety checks.

**Flow**: Load state → confirm (unless `force=True`) → cleanup OIDC → cleanup HTTPS/DNS → terminate environment → if no other envs: cleanup IAM + S3 + app → delete state

**Safety**: Only deletes shared resources (IAM, S3, app) if no other environments exist

### support.py
Shared AWS utilities and helpers.

**Key Helpers**:
- `aws_handler`: Decorator for AWS error handling
- `wait_for_env_status()`: Polls until target status
- `manage_iam_role()`: 1:1 local→cloud policy sync
- `find_environment_load_balancer()`: Finds ALB by tags
- `preserve_https_config()` / `restore_https_config()`: HTTPS preservation during updates

**IAM Policy Sync** (1:1 local files → AWS):
- Compares content, creates new policy versions when changed
- Deletes AWS policies not in local dir
- Maintains 5 versions max
- Naming: `{role_name}-{policy_filename}`

### cli.py
Click CLI wrapper around Python API. Maps CLI options to function kwargs. Loads `.env` via `dotenv.load_dotenv()`.

**Auto-loading**: Calls `load_app_env_vars(deployment_env)` to auto-pass app vars to EB. Default `deployment_env=".env.lb"`.

## State Management

**File**: `.elasticbeanstalk/config.yml` (YAML, EB CLI compatible)

**Structure**:
- Standard sections: `branch-defaults`, `global` (for EB CLI compatibility)
- Custom section: `lazy_beanstalk` (our state - EB CLI ignores it)

**Change Detection**: Compares current config vs `lazy_beanstalk` section state. Triggers environment update if changes detected in: `instance_type`, `spot_instances`, `min/max_instances`, `platform`, `region`, `env_vars`, `tags`.

## Design Decisions

### v1 → v2 Migration Rationale

**Why pip package?** Original template approach required copying deployment code into every project. Pip install = single source of truth, easy updates.

**Why smart defaults?** Original YAML config was verbose. Defaults enable `lb ship` with zero config.

**Why state file?** Needed change detection for intelligent updates (update vs recreation). Chose EB CLI format for `eb logs`, `eb ssh` compatibility.

**Why user Dockerfile?** Original auto-generated Dockerfiles couldn't handle all package managers. User's Dockerfile = full control, less complexity.

**Why environment variables?** Reduces config file verbosity. Hybrid `LB_*` with fallbacks enables reuse of standard vars (`AWS_REGION`, `OIDC_*`).

**Why auto-OIDC in secure?** User workflow is typically `lb ship && lb secure && lb shield`. Auto-detection reduces to `lb ship && lb secure`.

## Testing

**Automated**: `pytest` (9 tests covering config, ship, secure, shield, scrap)

**Manual**: `app/` contains demo terminaide chatline app for end-to-end testing

## AWS Resources

See @README.md for user-facing resource docs. Naming conventions:
- IAM roles: `{app_name}-eb-role`, `{app_name}-ec2-role`
- S3 bucket: `elasticbeanstalk-{region}-{app_name.lower()}`
- App versions: `v{YYYYMMDD_HHMMSS}`

## Gotchas & Implementation Notes

**Tags**: Only settable at environment creation, not updates (AWS limitation)

**Platform changes**: Can't change platform after creation (AWS limitation). Code warns but continues.

**HTTPS preservation**: Environment updates would lose HTTPS config. Fixed via `preserve_env_state()` / `restore_env_state()` in ship.py.

**Bundle creation**: Must exclude `.git` and `.env*` explicitly (not in `.gitignore`). Must filter `os.walk()` dirs list in-place to prevent descending into excluded dirs. `.env*` exclusion ensures secrets never uploaded.

**Circular import**: `secure.py` imports `shield()` for auto-OIDC. Works because import is at module level.

**Dependencies**: See @pyproject.toml. Key: `boto3`, `pyyaml`, `click`, `python-dotenv`

## Development Workflow

**Before committing**:
1. `pytest` (all tests must pass)
2. Update @README.md if user-facing changes
3. Update @CLAUDE.md if architecture changes
4. No duplication between docs (README = user, CLAUDE = maintainer)

**Commit style**: See @~/.claude/CLAUDE.md global instructions

## Known Limitations

- CLI doesn't support passing app `env_vars` (use Python API)
- Can't change platform/LB type after creation (AWS limitation)
- Can't update tags after creation (AWS limitation)
