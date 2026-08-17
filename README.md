# atlasview-prod-jwks

Public JWK sets for AtlasView production authentication.

**This repository is a production trust root.** The Memory Bus fetches
`memory-bus/jwks.json` directly from `main` at runtime:

```
MEMORY_BUS_JWKS_URL=https://raw.githubusercontent.com/Ruptiv/atlasview-prod-jwks/main/memory-bus/jwks.json
```

Anything merged to `main` is immediately trusted to authenticate production
requests. There is no staging step and no approval prompt between a merge and
production trust. Treat every change here as a production security change.

## Guardrails

| Guardrail | Mechanism |
|---|---|
| Structural + cryptographic validation | `scripts/validate_jwks.py`, run by CI on every PR and push |
| No private key material published | validator rejects `d`, RSA CRT factors, and `k` |
| No in-place key substitution | validator compares each existing `kid` against the base commit |
| Human review | `CODEOWNERS` + branch protection on `main` |

Run the validator locally before opening a PR. Two steps rather than process
substitution, because `<(...)` does not work under Git Bash on Windows:

```bash
git show origin/main:memory-bus/jwks.json > /tmp/baseline-jwks.json
```

```bash
python3 scripts/validate_jwks.py memory-bus/jwks.json --baseline /tmp/baseline-jwks.json
```

## Currently published keys

| `kid` | Purpose |
|---|---|
| `prod-jwt-key-2` | Production Memory Bus recall/actor tokens |
| `dev-jwt-key-1` | Legacy development key, slated for removal. Removal is sequenced behind confirming that no trusted consumer still presents tokens signed by it. |

## Rotating a signing key

The cardinal rule: **rotation adds a new `kid`; it never repoints an existing
one.** Verifiers cache by `kid`, so editing an existing key's `x`/`y` in place is
indistinguishable from a key-substitution attack and will either break or hijack
every cached verifier. CI enforces this.

The ordering below exists because publication and signing are separate events,
and signing with a key the verifier population has not yet observed causes an
immediate outage.

1. Create the new key version (KMS; see the `infra` repo's
   `terraform/environments/prod/kms.tf`). Do not let it sign yet.
2. Derive the JWK from the KMS **public** key and open a PR adding it
   *alongside* the current key. Two keys are published at once, on purpose.
3. Merge after code-owner review and green CI.
4. Prove propagation: every verifier population must resolve the new `kid`
   before anything signs with it. Raw GitHub content and each verifier's own
   JWKS cache both add delay.
5. Switch signing to the new key version.
6. Hold both keys published for the overlap window (2 hours) so tokens signed by
   the old version stay verifiable for their full lifetime.
7. Disable the old KMS version. Keep it disabled — do not destroy it.
8. Remove the old JWK in a separate PR, only after no unexpired token could
   still carry it.
9. Schedule destruction of the old KMS version after its retention period
   (30 days). This is a separate, witnessed, one-way action.

### Emergency removal (suspected key compromise)

Removing a `kid` here does **not** take effect instantly — verifiers hold a
JWKS cache. Removal starts a clock, it does not stop authentication. Use the
Bus-side deny controls and issuance freeze to stop acceptance immediately, then
remove the key, then force verifier refresh or restart. Record the incident
reference in the PR.
