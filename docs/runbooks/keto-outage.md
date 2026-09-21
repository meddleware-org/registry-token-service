# Runbook — Keto outage (authorization service down)

**Severity:** High (registry-wide). **Fail mode:** closed (by design).

The token service delegates every authorization decision to **Ory Keto**. If Keto is unreachable or
returns a non-success response, the service returns `503` and issues **no** token. Because the CNCF
`distribution` registry requires a valid token for every push and pull, a Keto outage halts
**all authenticated registry traffic** — this is intentional (fail-closed; see
[SECURITY.md](../../SECURITY.md) invariant 1 and [CLAUDE.md](../../CLAUDE.md) architectural
invariant 1). The service never fails open.

## Impact

- New `docker pull` / `docker push` (and CI image pulls) against `registry.meddleware.co.uk` fail
  while Keto is down.
- Already-issued tokens keep working until they expire (`TOKEN_TTL`, minutes), so in-flight pulls may
  briefly succeed before clients re-request a token and hit the `503`.
- No data loss and no security exposure — a closed gate denies, it does not leak.

## Detection

- **Symptom from clients:** `docker` reports auth failures; CI image steps fail pulling/pushing.
- **Token service logs:** `503` responses with `"authz service unavailable"` (Keto path;
  `cmd/server/main.go`). A Hydra outage instead logs `"auth service unavailable"` — that is a
  *different* dependency (see "Not Keto?" below).
- **Token service health:** `GET /healthz` on the pod stays `200` (the service itself is up — it is
  the *dependency* that is down), so liveness/readiness probes do **not** flap. Diagnose by the
  `503` rate on `/token`, not by `/healthz`.
- **Keto health:** check the Keto read API directly:
  ```bash
  kubectl -n auth get pods -l app.kubernetes.io/name=keto
  kubectl -n auth logs deploy/keto --tail=100
  # from a debug pod that NetworkPolicy allows, or via port-forward:
  kubectl -n auth port-forward svc/keto-read 4466:4466 &
  curl -sS localhost:4466/health/ready
  ```

## Immediate mitigation

1. **Confirm it is Keto**, not the token service or Hydra (see "Not Keto?").
2. **Restore Keto read API availability** — the fastest lever depending on cause:
   - Pod crashloop / OOM: `kubectl -n auth rollout restart deploy/keto`; check resources/limits.
   - Bad config/migration: roll back the last Keto change (`kubectl -n auth rollout undo …`).
   - DB backing Keto down: restore the Keto datastore, then restart Keto.
   - Network: verify `k8s/base/auth/networkpolicy.yaml` still permits the token-service pod
     (`registry` ns) → Keto `:4466`; a bad NetworkPolicy edit can sever the path.
3. **Do not** work around the outage by bypassing Keto (no allowlists, no fail-open patch) — that
   would grant unauthorized registry access. The correct posture during the outage is denied traffic.
4. Communicate: pushes/pulls are paused cluster-wide until Keto recovers.

## Recovery validation

```bash
# Keto ready again?
curl -sS localhost:4466/health/ready        # -> {"status":"ok"}

# Token service issues tokens again (expect 200 with a JWT for an authorized client):
curl -sS -u "$CLIENT_ID:$CLIENT_SECRET" \
  "https://token.meddleware.co.uk/token?service=registry.meddleware.co.uk&scope=repository:meddleware-org/static-server:pull"

# End-to-end:
docker pull registry.meddleware.co.uk/meddleware-org/static-server:latest
```

Token-service `503` rate on `/token` should return to zero.

## Not Keto? (differential)

| Symptom | Likely cause | Where |
| --- | --- | --- |
| `503 "authz service unavailable"` | **Keto** read API down/unreachable | this runbook |
| `503 "auth service unavailable"` | **Hydra** token endpoint down (credential validation) | check `kubectl -n auth … hydra` |
| `500` / panic / pod not ready | token-service itself (e.g. signing key mount) | token-service logs; see SECURITY.md "Signing-key custody" |
| `400 service mismatch` | client sent wrong `service` param | client misconfig, not an outage |

## Prevention

- Run Keto with ≥ 2 replicas and a PodDisruptionBudget so a single node drain cannot take it down.
- Set readiness probes + resource requests/limits on Keto to avoid OOM crashloops.
- Ensure the Keto datastore is HA / backed up.
- Gate changes to `k8s/base/auth/networkpolicy.yaml` and the mutual-auth policy in review — a
  NetworkPolicy regression is a common cause of a "Keto is up but unreachable" outage.
