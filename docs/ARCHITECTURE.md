# Architecture & Decisions — Agentic Payments Sandbox

> A product-owner's guide to **what** we built and **why**. Read this first; the
> code, the [HAM protocol spec](./HAM-PROTOCOL.md), and the
> [README](../README.md) go deeper.

---

## 1. The one-paragraph summary

We built a working, **testnet-only** sandbox where an AI agent pays a merchant
for goods using the **x402** internet-payment protocol — and, crucially, where
every payment is gated by a **cryptographically signed authorization from a
verified human**. The demo scenario is an agent buying over-the-counter items
from a simulated "CVS." The lasting deliverable is the authorization layer: a
**Human Authorization Mandate (HAM)** that answers the question agentic commerce
keeps dodging — *which human approved this agent to spend, and within what
limits?*

---

## 2. The problem we're solving

Agentic payments are arriving fast (Coinbase x402, Google AP2, Stripe, Visa/MC
pilots). The plumbing — letting an agent move money over HTTP — is largely
solved. The **trust gap** is not:

- An agent with a funded wallet can spend with **no verifiable link** back to a
  consenting human or an agreed budget.
- Merchants can't prove a real, authorized person stood behind a purchase →
  **dispute, fraud, and legal exposure**.
- Buyers have **no enforced guardrails** — "spend up to $50 at pharmacies this
  week" isn't something today's rails express or enforce.

This project closes that gap with a concrete, testable design.

### Goals

1. **Prove the payment rail works** — a real x402 settlement, agent → merchant.
2. **Bind a human identity to the agent's authority** — OIDC login → signed,
   scoped mandate.
3. **Make it safe** — no corrupt/double-charge states; spending stays within the
   signed budget; everything independently validated server-side.
4. **Validate the experience** for both buyer and merchant (the UX/legality lens).
5. **Be extensible** — a clean foundation for evolving the human-authorization
   protocol.

### Explicit non-goals (for this sandbox)

- No mainnet, no real funds, no real wallet (testnet + faucet only).
- CVS is **simulated** — no real CVS API exists for x402. The storefront is
  mocked; the payment + authorization rails are real.
- Not a production identity provider or custody solution.

---

## 3. Core concepts (glossary)

| Term | What it is | Why it matters here |
|---|---|---|
| **x402** | An open protocol that revives HTTP `402 Payment Required`: the server challenges with payment terms, the client pays and retries. | The payment rail. Coinbase-led, TypeScript-first, multi-chain. |
| **Facilitator** | A service that verifies a payment and settles it on-chain, so merchants don't run blockchain infra. | We use the free testnet facilitator; offline we use a mock that implements the same interface. |
| **EIP-3009 `transferWithAuthorization`** | A USDC feature: the payer *signs* an authorization; someone else submits it. | Makes payment **gasless for the agent** — it needs test USDC, not ETH. The signed `nonce` gives replay protection. |
| **OIDC / OAuth** | The standard for "log in as a verified human" and get an identity token. | How we establish *who* the human is. Local issuer for offline; Auth0 for real. |
| **Mandate** | A signed statement of authorization (from Google's AP2 model: Intent → Cart → Payment). | The unit of "a human authorized this." |
| **HAM** (our contribution) | **Human Authorization Mandate** — an AP2-style mandate chain with the **OIDC identity bound in**. | The research artifact: it ties a verified human to an agent's scoped spending. See [HAM-PROTOCOL.md](./HAM-PROTOCOL.md). |
| **Settlement** | The actual on-chain movement of USDC. | Happens **asynchronously**, after the merchant grants access. |

---

## 4. System at a glance

A DRY [npm-workspaces](https://docs.npmjs.com/cli/using-npm/workspaces) monorepo.
The shared core is defined **once** and imported everywhere, so a payment shape,
a validation rule, or the order lifecycle can never drift between the agent and
the merchant.

```
packages/
  shared/     DRY core: wire schemas, money math, ORDER STATE MACHINE,
              HAM mandate model + scope validators, payment validators,
              the Signer interface, one clock
  merchant/   "mock-CVS" seller: x402 paywall + RESILIENT FACILITATOR
              (retry / idempotency / transaction-lock), ORDER LEDGER,
              MANDATE GATE (+ cumulative spend ledger)
  agent/      headless buyer: CDP Server Wallet or viem key -> x402 client
  identity/   OIDC verifier (local + Auth0) + mandate SIGNING/VERIFICATION
              + the Authorization Service
apps/
  console/    one-command browser demo (buyer + merchant panels)
```

### The two flows

**A. Payment (x402)** — how money moves:

```
Agent ──GET /buy/sku───────────────▶ Merchant
      ◀──402 + payment terms────────  (price, asset=USDC, payTo)
Agent  signs EIP-3009 authorization
      ──retry w/ X-PAYMENT──────────▶ Merchant ──verify──▶ Facilitator
      ◀──200 + receipt (AUTHORIZED)─  grants access
                                       … asynchronously …
                                       Merchant ──settle──▶ Facilitator ──▶ chain
Agent ──poll /orders/by-nonce──────▶ Merchant  (state: SETTLED, tx hash)
```

**B. Authorization (HAM)** — how a human approves the agent:

```
Human ──login──▶ OIDC IdP ──ID token──▶ Authorization Service ──verify──▶ Principal
Human ──"spend ≤ $5 on pharmacy items, 1h"──▶ Authorization Service
                                              signs an INTENT mandate (EdDSA)
Agent  attaches the signed Intent to every /buy
Merchant  verifies signature + Payment ⊆ Cart ⊆ Intent + cumulative cap
          BEFORE settling. Out-of-scope ⇒ refused, never charged.
```

---

## 5. Architectural decisions & rationale

Short ADR-style log. Each is a real fork we took, with the reasoning.

| # | Decision | Why | Trade-off / note |
|---|---|---|---|
| 1 | **TypeScript/Node, not Python** | The entire official x402 v2 stack (`@x402/*`, facilitator, AgentKit, reference agents) is TS-first. Python ports lag. | One language across agent/merchant/identity. |
| 2 | **Coinbase CDP Server Wallet** for the agent | Headless **MPC** signing (no browser, no seed phrase), **native x402**, built-in spend policies — the real replacement for "MetaMask, but for agents." | Needs a free CDP API key. Mitigated by a **viem-key fallback** behind a shared `PaymentSigner` interface. |
| 3 | **Base Sepolia + free facilitator + a mock** | Zero real-fund/real-wallet risk (the user's hard constraint). The mock implements the **same** `FacilitatorClient` interface, so the full flow runs offline with no keys. | Live settlement is a config swap (`FACILITATOR_MODE=http` + CDP key). |
| 4 | **Model settlement as asynchronous** | The x402 v2 middleware grants access on `verify` and **settles after the response**. We mapped this to the lifecycle: `verify → AUTHORIZED` (sync), `settle → SETTLED` (async). | The immediate receipt says "authorized"; the client polls for the settled tx. This matches real async-settlement systems. |
| 5 | **One resilient wrapper at the settlement seam** | All the "never double-charge / never corrupt state" guarantees live in **one** `ResilientFacilitatorClient` that wraps any facilitator: retry transient failures, **idempotent per nonce**, **transaction-lock** coalescing. | Centralizes the risky logic; trivially unit-tested with the mock. |
| 6 | **An explicit order state machine** | `CREATED→QUOTED→AUTHORIZED→SETTLING→SETTLED→REFUNDED` (+ `FAILED`/`EXPIRED`). Illegal transitions **throw**. | Corrupt/double-settled states become impossible by construction, not by convention. |
| 7 | **HAM = AP2 mandate chain + OIDC binding** | AP2 (Google) defines Intent→Cart→Payment mandates but leaves identity binding open. Auth0/Okta are AP2 identity partners. We bind the verified OIDC `sub` into a signed Intent — the missing piece. | This is the project's reusable research contribution. |
| 8 | **Authorize against the merchant's catalog price** | The gate builds the cart from **its own catalog**, not the agent's claimed amount, then checks the signed payment equals it. | Found via code review: trusting agent input would let cumulative caps be under-counted. |
| 9 | **Swappable "seams" everywhere** | `PaymentSigner`, `OrderStore`, `FacilitatorClient`, `IdentityVerifier` are all interfaces with a real impl + a local/mock impl, injected. | Lets us test offline and swap CDP/Auth0/SQLite in later **without touching callers**. This is the project's load-bearing pattern. |
| 10 | **In-process demo console** | Boots merchant + identity + agent in one process and proxies the merchant API (no CORS), serving a no-build vanilla-JS UI. | One command (`npm run console`) to validate the buyer + merchant UX. |
| 11 | **x401 + Proof VCs as the identity source for HAM** | Replace OIDC→Intent with a verifiable-credential presentation→Intent: the human selectively discloses identity (DCQL) and authorizes the payment (`transaction_data`) in one SD-JWT-VC presentation, which the AS verifies before signing the Intent. x402/merchant unchanged. | Proves "who authorized *this* payment". Proof's flow is a human-in-the-loop redirect, so it's an up-front step, not a per-request gate. See [X401-PROTOCOL.md](./X401-PROTOCOL.md). |
| 12 | **VC seam built on the Proof/SD-JWT stack** | `packages/credentials` uses `@sd-jwt/sd-jwt-vc` + `@owf/crypto` (Proof's own libs, WebCrypto) so the same code issues/holds/presents/verifies offline AND runs in the browser wallet. `VerifiableCredentialVerifier` = `localVcVerifier` (mock) / `proofVcVerifier` (live). | Live Proof is a config swap (`PROOF_MODE=live`). The mock implements the real interface, so tests exercise the real verification path. |
| 13 | **Build-based (Vite + Svelte) wallet demo** | The wallet needs to bundle `@sd-jwt/*` for *real* in-browser selective disclosure + animated protocol visuals, which the no-build console (decision 10) can't do cleanly. | A second app (`apps/wallet-demo`); the original console stays no-build. |

---

## 6. Safety & correctness — and how each is enforced

These were explicit requirements ("nothing gets into a corrupt or problematic
state"). Each is enforced in code **and** covered by tests.

| Guarantee | Mechanism | Where |
|---|---|---|
| Payment parameters are valid | Zod schemas + independent validator (asset allowlist, exact amount, recipient, time window) — defense-in-depth on top of the facilitator | `shared/validation.ts` |
| No illegal/corrupt order states | State machine rejects any transition not on the allowed graph | `shared/state-machine.ts` |
| Never double-charge on retry | Settlement is **idempotent per EIP-3009 nonce** and **lock-coalesced**; only *transient* errors retry | `merchant/facilitator/resilient.ts` |
| Replayed checkout ≠ double order | HTTP idempotency key → returns the existing order, skips payment | `merchant/server.ts` |
| Human actually authorized | EdDSA Intent signature verified against the Authorization Service's trusted key | `identity/mandate.ts`, `merchant/mandate-gate.ts` |
| Spend stays in budget | `Payment ⊆ Cart ⊆ Intent` (per-purchase cap) **plus** a cumulative **reserve→commit/release** ledger tied to settlement | `merchant/mandate-gate.ts` |
| No leaked reservations | A reservation is released if the request doesn't end `200` | `merchant/mandate-gate.ts` (regression-tested) |

**Testing:** 79 unit + integration tests (Vitest). Two offline end-to-end suites
run the full agent→merchant→facilitator round trip with **no keys or funds** —
one for the payment slice, one for mandate enforcement. A **high-effort,
workflow-backed code review** (40 agents) was run after the authorization layer;
all findings were applied, including two real bugs (the reservation leak and the
catalog-price fix above).

---

## 7. Buyer & merchant experience (the UX / legality lens)

- **Buyer:** logs in as a verified human, **reviews and signs** an explicit
  budget (cap, categories, expiry), then watches the agent transact strictly
  within it. Refusals are clear ("categories not authorized"). This is informed
  consent with enforced limits — not a blank check.
- **Merchant:** sees not just a payment but a **non-repudiable authorization
  chain** proving a known human approved the purchase within scope, plus the
  settlement tx and a clean order lifecycle for refunds/disputes.
- **Legality posture:** consent capture, disclosed agent involvement, enforced
  spend limits, and an auditable "who authorized what" trail — the building
  blocks regulators and dispute systems will expect.

---

## 8. What's built vs. pending

| | Status |
|---|---|
| DRY core, state machine, validators, HAM model | ✅ |
| x402 payment slice (offline settlement via mock) | ✅ |
| OIDC + HAM enforcement | ✅ |
| Buyer/merchant UX consoles | ✅ |
| x401 + Proof VC identity (DCQL selective disclosure + payment binding) → HAM | ✅ (offline; `packages/credentials`, `apps/wallet-demo`) |
| Three wallet workflows + **delegated** (autonomous) mandate w/ cumulative-cap enforcement | ✅ (`WALLET_FLOW`, `/api/agent/run`; `e2e-delegated`) |
| Mandate **revocation** (issuer kills a standing Intent; merchant refuses) | ✅ (in-process registry; `e2e-revocation`) |
| Orchestrator auth + per-client session isolation | ✅ (signed-cookie sessions + token gate; `e2e-demo-auth`) |
| **Live** Base Sepolia settlement | ⏳ needs free CDP key + faucet USDC |
| **Real** Auth0 identity | ⏳ one-line `auth0Verifier` swap + tenant creds |
| **Live** Proof VC presentation | ⏳ `PROOF_MODE=live` + Proof OAuth app (`PROOF_CLIENT_ID`, registered redirect URI, sandbox user email) |

### Deferred for production (intentional in-process seams — swap, don't rewrite)

The following are deliberately **in-process for the offline demo**, each behind a
swappable seam so productionizing is an injection rather than a rewrite. Revisit
these **before any real-funds or multi-instance deployment**:

- **Revocation channel** — `RevocationChecker` (`packages/identity/src/revocation.ts`)
  is today an in-process `RevocationRegistry` shared between the issuer (writer) and
  the merchant (reader). **Later:** back it with an **issuer revocation/status
  endpoint** the merchant queries (OCSP / status-list style), and decide the
  fail-open-vs-fail-closed policy when the issuer is unreachable. Designed to mirror
  the `IntentSpendLedger` / `MandateVerifier` injection pattern, so this is a reader
  swap, not a gate rewrite.
- **Spend-cap ledger (durability + scope)** — `IntentSpendLedger` is in-memory and
  per-merchant-process, so the cumulative cap resets on restart and isn't global
  across `merchantAllowlist`. **Later:** a shared/persistent, cross-merchant ledger.
- **Orchestrator session store** — per-client sessions live in an in-memory `Map`
  (single process). **Later:** a shared/persistent session store (+ `Secure`
  cookies behind TLS).

## 9. How to extend it

- **Swap a backend** (real facilitator, SQLite orders, Turnkey wallet, Auth0):
  implement the existing interface and inject it — no caller changes.
- **Evolve the protocol:** the HAM model + verifiers are a self-contained module
  in `identity/` and `shared/mandates.ts`; see [HAM-PROTOCOL.md](./HAM-PROTOCOL.md)
  for the data model, verification rules, and threat model.
- **Add a settlement scheme / chain:** the x402 v2 packages support more; the
  `FacilitatorClient` seam and scheme registration are already in place.

---

## 10. File map (where to look)

| Area | Path |
|---|---|
| Wire schemas, constants, money | `packages/shared/src/{schemas,constants,money}.ts` |
| Order state machine | `packages/shared/src/state-machine.ts` |
| HAM model + scope validators | `packages/shared/src/mandates.ts` |
| Payment-parameter validators | `packages/shared/src/validation.ts` |
| Resilient settlement | `packages/merchant/src/facilitator/resilient.ts` |
| Mandate gate + spend ledger | `packages/merchant/src/mandate-gate.ts` |
| OIDC + mandate signing | `packages/identity/src/{oidc,mandate,keys}.ts` |
| x401 + Proof VC seam (SD-JWT-VC, DCQL, transaction_data, verifier) | `packages/credentials/src/` |
| VC→Intent issuance | `packages/identity/src/mandate.ts` (`issueIntentFromPresentation`) |
| Agent wallet + x402 client | `packages/agent/src/{wallet,x402-client,buyer}.ts` |
| Demo console (OIDC + HAM) | `apps/console/` |
| x401 wallet demo (VC → HAM → x402) | `apps/wallet-demo/` |
