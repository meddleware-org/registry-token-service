# Runbook — rotate the token-signing key

The signing key forges any registry token, so it is rotated **with overlap**: the registry trusts
the new public key before the service starts signing with it, and drops the old one only after the
last old token has expired. Rotating in one step ("replace the key and restart both") leaves a
window in which every token is refused.

`kid` is the RFC 7638 thumbprint of the signing key, so the registry selects the right key from its
trust bundle by itself.

## Planned rotation

1. **Generate** a new RSA key of at least 4096 bits (the service refuses a weaker one at startup).
   Keep the private half out of the repository and out of shell history.
2. **Add the new public key to the registry's trust bundle** (`rootcertbundle`), next to the old
   one, and roll the registry. Both keys now verify.
3. **Replace the `token-service-keys` Secret** (`signing.key`, mode 0440) with the new private key
   and restart the token service. New tokens carry the new `kid`.
4. **Wait one `TOKEN_TTL`** (at most 3600 s; the deployment uses 300 s) so no token signed with the
   old key is still valid.
5. **Remove the old public key** from the registry's trust bundle and roll the registry.
6. **Check** with a real push and pull, and that the status page's registry chain check is
   operational. Record the date in `deployments` / the operator notes.

## Suspected compromise of the signing key

Speed over overlap: an attacker holding the old key can mint tokens for any repository.

1. Replace the trust bundle with **only** the new public key and roll the registry (the old key is
   no longer trusted; every outstanding token stops working).
2. Replace the Secret with the new private key and restart the token service.
3. Expect pushes and pulls to fail between steps 1 and 2: that window is the cost of cutting the
   attacker off first. Keep it short by preparing both changes before applying either.
4. Review the token service's `token issued` log lines (client id, requested and granted scopes) for
   the period the key may have been exposed, and the registry's access log for pushes you do not
   recognise.
5. Rotate the Hydra client secrets the service saw only if the host itself was compromised.

## What this does not cover

Hydra client secrets are rotated in Hydra and in whatever holds them (CI secrets, `registry-auth-proxy`'s
mounted file), not here.
