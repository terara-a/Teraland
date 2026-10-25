# Working on Teraland

## Goal and current implementation

Teraland is a personal OpenID Provider PoC targeting the OpenID Foundation's
OpenID Federation OP automatic-registration conformance plan. It runs on
**TypeScript + Cloudflare Workers + SQLite-backed Durable Objects**. Go was
replaced in merged PR #2; do not use Go-era commands or reintroduce the old server.

Read `README.md` for setup, configuration, deployment, features and limitations.
The official test plan is
`openid-federation-entity-joined-to-test-federation-op-test-plan`.
**No public Cloudflare deployment or official conformance pass has been verified.**
Local tests and GitHub CI are separate evidence; never describe them as official
certification. Update this statement only after verifying an actual deployment or
suite run.

Respond to the user in Japanese unless they request another language. Prefer
executing the requested work through verification over asking for confirmation
of routine reversible steps.

## Repository map

- `src/index.ts`: Worker configuration, discovery, login, OIDC endpoints.
- `src/federation.ts`: bounded discovery, pinned trust chains, effective RP
  metadata and signed request validation.
- `src/crypto.ts`: JOSE operations, public-key validation, registered algorithm
  constraints, hashes and comparisons.
- `src/state.ts`: Durable Object transactions, one-time consumption, replay
  records and expiration cleanup.
- `src/http.ts`: bounded body reading; `src/types.ts`: shared types and helpers.
- `scripts/setup-local.mjs`: private local configuration generation.
- `test/*.test.mjs`: Node test runner with real Miniflare/workerd and persistent
  SQLite Durable Objects. Remote federation documents are mocked at outbound
  fetch, not by bypassing signature or trust verification.
- `wrangler.jsonc`: bindings, migrations and non-secret deployment settings.
- `.github/workflows/ci.yml`: install, formatting, typecheck and integration tests.

## Development and verification

Use the existing checkout. Cloud tasks are isolated already; do not create a Git
worktree unless explicitly requested. After the user reports a merge, inspect
local changes, fetch `origin/main`, and branch from that ref for new work. Do not
reset or overwrite local work. Merges may squash commits: compare contents, not
just commit ancestry.

Use Node.js 24 (CI's version) and npm with the committed lockfile:

```sh
npm ci
npm run typecheck
npm run format:check
npm test
```

`npm test` already runs `npm run build` (Wrangler deployment **dry-run**), then
`node --test test/*.test.mjs`. Do not repeat the build separately without a reason.
Preserve command exit status when redirecting test output, and inspect both the
test summary and exit code. `npm run format` formats source, tests, scripts,
configuration and README; format `AGENTS.md` explicitly with Prettier when editing
it. Documentation-only changes do not require the full integration suite.

For local startup, run `npm run setup:local` **only if `.dev.vars` does not exist**,
then `npm run dev`. Default local issuer is `http://localhost:8787`; the development
HTTP exception is restricted to localhost and `DEV_MODE=true`. Verify `/healthz`,
discovery and signed entity configuration with internal requests. Do not confuse
an open port with functional validation.

In the Codex cloud workspace, if defaults point to unwritable home directories:

```sh
export npm_config_cache=/workspace/.cache/npm
export XDG_CONFIG_HOME=/workspace/.cache/config
```

Node is supplied by the environment; locate it before attempting installation.
Do not repurpose `HOME`, disable verification, or edit global shell files to fix
cache/log paths. Wrangler's inability to fetch optional `Request.cf` metadata in
this cloud environment has not prevented local startup; check functional
responses before diagnosing it as a blocker.

## Security invariants to retain

- Trust anchors are explicitly pinned public JWKS. Self-signing alone does not
  establish trust. Check signatures, identifiers, times and child-key bindings
  along every path. Do not silently ignore unsupported policy or constraints.
- Enforce effective RP metadata, including registered request/assertion signing
  algorithms and supported ID-token requirements, in addition to JWK constraints.
- Only configured, exact DNS hostnames in `FEDERATION_HOSTS` may be fetched.
  Require HTTPS/443, reject IP literals (including shared address space and mapped
  IPv6), do not follow redirects, and retain size/time/request-count limits.
  Workers cannot perform Go-style DNS-to-socket pinning; do not claim equivalent
  DNS filtering. Approved hosts must be trusted by the operator.
- Keep code consumption and replay detection transactional in Durable Objects.
  An isolate-global map or eventually consistent KV is not a replacement.
- PAR/login request lifetime cannot exceed request-object or verified trust
  expiration. A newly issued code gets its own 60 seconds, capped by the verified
  RP's `trust_exp`, not by the consumed request's remaining lifetime.
- Record `auth_time` at login, not token exchange. Support GET and POST UserInfo.
- Use per-request CSRF cookies so tabs do not invalidate each other. Keep Origin
  checks, escaping, cache suppression and a login-page CSP that permits only the
  already-validated callback origin alongside self.
- Entry-point path checks in Node scripts use `pathToFileURL`, not `new URL(path)`.
  Preserve existing private local configuration on repeated setup.

Never print, commit, overwrite or copy private JWKs/passwords into instructions.
`.dev.vars`, `.wrangler/` and `.local/` are ignored local state. Go-era private JWKs
may still exist in `.local/teraland/`; they remain usable for migration and must
not be deleted or rotated casually. Production uses Cloudflare Secrets for
`SIGNING_JWK`, `ENCRYPTION_JWK`, `TERALAND_USERNAME`, `TERALAND_PASSWORD`.
Deployments require the real HTTPS issuer, approved federation hosts and pinned
anchors; avoid deploying placeholder settings. Do not run `npm run deploy` or
create tunnels merely to validate a local change.

## PR, CI and review workflow

The user has asked for PR changes to be carried through push, CI verification and
reply comments. When handling a PR/review task:

1. Read current PR status and all relevant review comments using `gh`. Verify the
   head SHA and local changes; do not assume the last-mentioned PR is still open.
2. Investigate each finding, add meaningful regression coverage for behavior
   changes, implement fixes and run relevant checks.
3. Commit/push to the PR's branch without force-pushing. For new work after a
   merge, use a new branch and a reviewable PR; do not merge it yourself.
4. Check both push and pull-request CI for the **new full head SHA**. Old successful
   runs do not verify the update. Wait through active runs and investigate failures.
5. Reply with the fix commit, concrete behavior and validation. Write multiline
   bodies to a temporary file and use `--body-file` or `gh api -F body=@file`.
   Do not claim browser/Windows/public-cloud checks that were not executed.

Useful commands (substitute the actual PR/branch):

```sh
gh pr view NUMBER --json state,isDraft,headRefName,headRefOid,reviews,statusCheckRollup
gh api repos/terara-a/Teraland/pulls/NUMBER/comments
gh run list --repo terara-a/Teraland --branch BRANCH --json databaseId,headSha,status,conclusion,event,url
gh pr checks NUMBER --repo terara-a/Teraland
```

GitHub HTTPS Git authentication and GitHub API authentication/access are separate.
An absent token variable or CLI login prompt alone is not proof of missing Git
access. API access previously returned a network 403, then became usable after
`api.github.com` was allowed. Retry the required operation before requesting new
credentials; inspect variable names/presence only.

During an active task, wait for requested Copilot reviews and handle their
findings through CI and replies. There is **no always-on background monitor**
after a chat turn ends; do not promise one or claim that a new review will
restart Codex automatically. Persistent monitoring automation is not implemented.
