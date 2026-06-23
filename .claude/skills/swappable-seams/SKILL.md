---
name: swappable-seams
description: The load-bearing architectural patterns for this agentic-payments codebase — swappable seams (interface + real impl + local/mock impl, injected), mocks that implement the REAL interface, a single resilient wrapper at a risky boundary, and the uniform ValidationResult. Use when adding a backend (wallet, facilitator, store, IdP), wiring a new external dependency, or writing offline tests, so new code matches the existing structure instead of diverging.
---

# Swappable seams — how this codebase scales cleanly

This project stays testable, offline-runnable, and DRY by following a few
patterns consistently. When you add capability, match these — don't invent a
parallel structure.

## 1. The swappable seam (the core pattern)

For any external dependency (wallet, facilitator, order store, identity
provider), define a **small interface**, provide **two implementations** — a
real one and a local/mock one — and **inject** the choice. Callers depend only
on the interface.

Existing seams (copy their shape):

| Seam | Interface | Real impl | Local/offline impl |
|---|---|---|---|
| Wallet | `PaymentSigner` (`shared/src/signer.ts`) | `createCdpSigner` | `createLocalSigner` (viem key) |
| Settlement | `FacilitatorClient` (`@x402/core`) | `HTTPFacilitatorClient` | `MockFacilitator` |
| Order persistence | `OrderStore` (`merchant/src/order-store.ts`) | (SQLite, later) | `MemoryOrderStore` |
| Identity (OIDC) | `IdentityVerifier` (`identity/src/oidc.ts`) | `auth0Verifier` | `localVerifier` |
| Identity (VC/x401) | `VerifiableCredentialVerifier` (`credentials/src/verifier.ts`) | `proofVcVerifier` | `localVcVerifier` |

Rules:
- Keep the interface **minimal** — only what callers actually need.
- Selection happens at the edge (a `create*` factory reading config/env), never
  scattered through call sites.
- A new backend = implement the interface + add it to the factory. **No caller
  changes.**

## 2. Mocks implement the REAL interface

The offline mock must implement the **same** interface as production, so tests
exercise real wiring — not a bypass. `MockFacilitator` implements
`FacilitatorClient` (verify/settle/getSupported) and returns a synthetic tx;
the full agent→merchant→facilitator round trip runs with no keys or funds
(`test/e2e.test.ts`). Do not add test-only branches in production code to make
things "work offline" — add a mock impl of the seam instead.

## 3. One resilient wrapper at a risky boundary

Cross-cutting safety (retry, idempotency, locking) belongs in **one** wrapper at
the boundary, not sprinkled across callers. `ResilientFacilitatorClient` wraps
*any* `FacilitatorClient` and adds retry-with-backoff (transient only), per-nonce
settlement idempotency, and transaction-lock coalescing. It's injected exactly
where the plain facilitator would go, and unit-tested against the mock with a
fake clock. New cross-cutting concern at a seam → extend/add a wrapper, keep it
deterministic (inject clock/sleep).

## 4. Uniform ValidationResult

Every validator returns `ValidationResult` (`shared/src/result.ts`):
`{ ok: true } | { ok: false; violations: string[] }`, built with `collect([...])`
of "violation string or null" checks. This makes failures uniform, composable,
and easy to surface in HTTP responses. New validation → return a
`ValidationResult`, don't throw ad-hoc or return booleans.

## 5. Single source of truth (DRY)

- Wire shapes, money math, the order state machine, mandate scope rules, and the
  clock live **once** in `packages/shared` and are imported everywhere. Don't
  redefine a payment shape or re-derive `Date.now()/1000` locally — import it
  (`nowSeconds`, `cartItemsTotal`, the Zod schemas).
- Authorize against **server-owned truth** (e.g. the catalog price), never
  against values supplied by the counterparty.

## 6. Entry-point guard

Files that can run standalone *and* be imported gate their boot with
`process.argv[1] === fileURLToPath(import.meta.url)` — never `endsWith("x.ts")`
(two entry files can share a basename and falsely both "run").

## Checklist for new work
- [ ] New external dep behind a minimal interface with real + mock impls?
- [ ] Mock implements the real interface (no prod test-branches)?
- [ ] Cross-cutting safety in one injected wrapper, clock/sleep injected?
- [ ] Validators return `ValidationResult`?
- [ ] Shared shapes/helpers imported from `packages/shared`, not duplicated?
- [ ] Tests: a unit test for the new impl + offline E2E still green?
