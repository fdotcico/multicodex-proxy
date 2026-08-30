# Security Review Report

## Executive Summary

This repository is a TypeScript/Express proxy with an embedded React admin dashboard. The most serious issues are insecure deployment defaults around authentication and several admin-controlled outbound URLs that can be turned into SSRF primitives if the admin surface is exposed. I did not find a direct secret-leak or auth-bypass regression in PR #13 or the `ebe050c` quota-detail fix, but PR #16 introduced a new low-severity abuse surface by trusting caller-supplied session identifiers for server-side affinity.

## Critical Findings

### SEC-001

- Rule ID: EXPRESS-AUTH-001
- Severity: Critical
- Location: `docker-compose.yml:28`, `src/server.ts:271-275`, `src/server.ts:443`
- Evidence:

```yaml
# docker-compose.yml:28-29
- ADMIN_TOKEN=change-me
- PROXY_API_KEY=${PROXY_API_KEY:-}
```

```ts
// src/server.ts:271-275
const token =
  req.header("x-admin-token") ||
  req.header("authorization")?.replace(/^Bearer\s+/i, "");
if (!token || !safeEqual(token, ADMIN_TOKEN))
  return res.status(401).json({ error: "unauthorized" });
```

```ts
// src/server.ts:443
app.use("/admin", adminGuard, adminRouter);
```

- Impact: A deployment based on the shipped `docker-compose.yml` is reachable on port `1455` with a known admin credential (`change-me`). An attacker who can reach the service can authenticate to the dashboard and fully administer accounts, traces, webhooks, and routing.
- Fix: Refuse to start when `ADMIN_TOKEN` is empty or equals known placeholders such as `change-me`, except under an explicit development-only override such as `ALLOW_INSECURE_DEFAULTS=true`.
- Mitigation: Keep the service behind a private network or reverse proxy ACL until startup hard-fails on weak admin tokens.
- False positive notes: If operators never use the provided compose file and always inject a strong secret, the immediate exposure is lower, but the repository still ships an unsafe default.

## High Findings

### SEC-002

- Rule ID: EXPRESS-AUTH-002
- Severity: High
- Location: `docker-compose.yml:29`, `src/server.ts:316-321`, `README.md:231-246`, `README.md:646-649`
- Evidence:

```ts
// src/server.ts:316-321
const proxyApiKeys = [
  ...configuredProxyApiKeys,
  ...store.getCachedProxyApiKeys(),
];
if (!proxyApiKeys.length || hasAdminSession(req)) {
  return next();
}
```

```md
<!-- README.md:646-649 -->
| `PROXY_API_KEY`  | empty | Optional Bearer or `x-api-key` required by HTTP and WebSocket proxy endpoints |
| `PROXY_API_KEYS` | empty | JSON object of application names to proxy keys |
```

- Impact: If no proxy API key is configured, the proxy becomes fail-open and forwards requests through stored upstream accounts for any caller. On an internet-exposed deployment this enables quota burn, anonymous use of paid upstream accounts, and abuse of any attached provider identities.
- Fix: Make proxy authentication fail-closed by default. If unauthenticated proxying is ever needed, require an explicit opt-in flag such as `ALLOW_UNAUTHENTICATED_PROXY=true` and surface a startup warning.
- Mitigation: Set `PROXY_API_KEY` or `PROXY_API_KEYS` everywhere outside local development, and restrict port `1455` at the network edge.
- False positive notes: This is a deployment-default issue rather than an exploit when operators already require proxy keys.

### SEC-003

- Rule ID: EXPRESS-SSRF-001
- Severity: High
- Location: `src/routes/admin/index.ts:98-101`, `src/routes/admin/index.ts:134-148`, `src/routes/admin/index.ts:464-486`, `src/routes/admin/index.ts:1001-1054`, `src/smart-routing-routes.ts:236-252`, `src/jobs.ts:713-723`
- Evidence:

```ts
// src/routes/admin/index.ts:98-101
function normalizeBaseUrl(value: unknown): string | undefined {
  const raw = String(value ?? "").trim();
  if (!raw) return undefined;
  return raw.replace(/\/+$/, "");
}
```

```ts
// src/routes/admin/index.ts:134-140
const endpoint = (key: string) => {
  if (!raw[key]) return undefined;
  const parsed = new URL(String(raw[key]));
  if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) {
    throw new Error(`${key} must be an HTTP(S) URL without credentials`);
  }
  return parsed.toString();
};
```

```ts
// src/routes/admin/index.ts:469-486
url = new URL(String(req.body?.url ?? ""));
...
policy.webhooks.push({
  id: randomUUID(),
  url: url.toString(),
  secret: randomBytes(32).toString("base64url"),
});
```

```ts
// src/smart-routing-routes.ts:236-252
const response = await fetch(healthUrl, {
  redirect: "error",
  signal: AbortSignal.timeout(3_000),
});
...
const response = await fetch(metricsUrl, {
  redirect: "error",
  signal: AbortSignal.timeout(3_000),
});
```

```ts
// src/jobs.ts:713-723
const response = await fetch(webhook.url, {
  method: "POST",
  redirect: "error",
  headers: {
    "content-type": "application/json",
    "x-multivibe-event-id": delivery.event_id,
    "x-multivibe-signature": `sha256=${signature}`,
  },
  body: payload,
  signal: AbortSignal.timeout(10_000),
});
```

- Impact: An attacker who gains admin access can configure the proxy to call arbitrary HTTP(S) targets, including loopback, RFC1918, or cloud metadata endpoints, via account `baseUrl`, capacity `healthUrl`/`metricsUrl`, or webhooks. Combined with `SEC-001`, this becomes remote SSRF on default compose deployments.
- Fix: Validate outbound targets against an allowlist or deny private, loopback, link-local, and metadata IP ranges by default. Keep an explicit escape hatch only for trusted operators who intentionally need internal URLs.
- Mitigation: Place the service in an environment where it cannot reach sensitive internal control planes or metadata endpoints.
- False positive notes: If admin access is already tightly controlled and outbound egress is filtered, exploitability drops, but the application still provides the primitive.

## Medium Findings

### SEC-004

- Rule ID: EXPRESS-HEADERS-001
- Severity: Medium
- Location: `src/server.ts:66-90`, `src/server.ts:452-468`, `web/index.html:1-10`
- Evidence:

```ts
// src/server.ts:66-67
const app = express();
app.use(createBodyParserMiddleware());
```

```ts
// src/server.ts:452-468
app.use(express.static(webDist));
app.get("*", (req, res, next) => {
  ...
  res.sendFile(path.join(webDist, "index.html"), (err) => {
    if (err) next();
  });
});
```

```html
<!-- web/index.html:1-10 -->
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>MultiVibe Dashboard</title>
</head>
```

- Impact: The app serves an admin dashboard but no `helmet()` middleware, no visible CSP, no frame restrictions, and no `app.disable('x-powered-by')`. That raises the blast radius of any future XSS or UI injection bug and leaves clickjacking and fingerprinting defenses to external infrastructure.
- Fix: Add `helmet()` early in the middleware chain, explicitly disable `x-powered-by`, and define at least a baseline CSP and `frame-ancestors` policy for the dashboard.
- Mitigation: If these headers are already set at the reverse proxy/CDN, verify them at runtime and document that the application depends on edge enforcement.
- False positive notes: This is defense-in-depth if an upstream gateway already injects the headers.

## Low Findings

### SEC-005

- Rule ID: EXPRESS-ABUSE-001
- Severity: Low
- Location: `src/codex-projects.ts:168-190`, `src/session-affinity.ts:18-69`, `src/routes/proxy/index.ts:2282-2318`
- Evidence:

```ts
// src/codex-projects.ts:181-189
for (const name of [
  CODEX_SESSION_FORWARD_HEADER,
  "thread-id",
  "session_id",
  "session-id",
  "x-session-id",
]) {
  const candidate = headerValue(normalized, name);
  if (candidate && candidate.length <= 200 && /^[a-z0-9._:-]+$/i.test(candidate)) {
    return candidate;
  }
}
```

```ts
// src/routes/proxy/index.ts:2282-2318
const affinityAccount = findSessionAffinityAccount(
  sessionAffinity,
  sessionAffinityEnabled,
  affinityApplication,
  codexSessionId,
  candidate.provider,
  quotaAwareAccounts,
);
...
sessionAffinity.remember(
  affinityApplication,
  codexSessionId,
  candidate.provider,
  selected.id,
);
```

- Impact: PR #16 added a process-wide affinity cache keyed by client-supplied session identifiers. Any caller who can hit the proxy can mint arbitrary session IDs to churn the cache or influence stickiness within the same application scope. This is mainly an abuse-control and fairness issue, not a direct privilege escalation.
- Fix: Only honor a signed/internal session header, namespace affinity by authenticated principal, and persist affinity only after a successful upstream response.
- Mitigation: Keep `CODEX_SESSION_AFFINITY=false` unless there is a demonstrated need, and require proxy API keys so anonymous callers cannot drive the cache.
- False positive notes: The cache is bounded (`CODEX_SESSION_AFFINITY_MAX_ENTRIES`) and application-scoped, which limits impact.

## Recent PR Review

- PR `#16` (`918f894`): Introduced `session-affinity.ts` and new routing behavior. I did not find an auth bypass, but it introduced `SEC-005` because server-side affinity trusts untrusted session headers.
- PR `#13` (`1de6798`): The quota reset lifecycle changes look like reliability hardening. I did not find a new direct security regression in the inspected diff.
- Commit `ebe050c`: The quota-detail preservation change only broadens the text used to classify quota errors and did not expose a new obvious secret leak in the inspected path.
- Commit `ffd3f40`: Positive signal. The web lockfile update appears to address a transitive dependency concern rather than introduce one.

## Residual Risks / Validation Gaps

- I reviewed source and recent diffs only. I did not run a live deployment attack simulation.
- I did not run dependency scanners such as `npm audit`; if you want, I can do a dependency-focused follow-up from `main`.
- I did not verify runtime headers at the reverse proxy or CDN layer, so header-related findings assume app code is the primary enforcement layer.
