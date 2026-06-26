# x401 + Proof VC Authorization — Protocol Notes v0.1

> How this sandbox combines **x401** (identity proof over HTTP) with **x402**
> (payment over HTTP) so that *the human who authorized an agentic payment is
> cryptographically provable* — and bound to the **specific payment** — while the
> human selectively discloses only the identity attributes a verifier asks for
> (via a **DCQL** query).

Status: working reference implementation — `packages/credentials`,
`apps/wallet-demo`, and `AuthorizationService.issueIntentFromPresentation`
(`packages/identity/src/mandate.ts`).

---

## 1. The idea in one paragraph

x402 moves money but is identity-agnostic. Our **HAM** layer already binds *which
human* approved an agent via a signed Intent — previously sourced from an **OIDC**
login. x401 replaces that identity source with a **verifiable-credential
presentation**: the verifier issues a `PROOF-REQUIRED` challenge carrying a DCQL
query (which claims it wants) and a **payment `transaction_data`** (what it wants
authorized); the holder's wallet returns a `vp_token` (an SD-JWT-VC + key-binding
JWT) that discloses **only the requested claims** and is bound to both the
challenge nonce and the payment. The verifier checks all of it, then issues the
HAM Intent that gates x402 settlement. So "who authorized *this* payment" is
answered by a selectively-disclosed, payment-bound credential.

---

## 2. Roles

| Role | In this repo | Responsibility |
|---|---|---|
| **Holder (Human)** | Proof wallet (live) / `LocalWallet` (offline) | Holds the SD-JWT-VC; selectively discloses claims; signs the KB-JWT over the nonce. |
| **Issuer** | Proof (live) / `LocalVcIssuer` (offline) | Issues the `proof_id_default` SD-JWT-VC, holder key bound via `cnf`. |
| **Verifier / Authorization Service** | orchestrator + `packages/credentials` + `AuthorizationService` | Builds the x401 challenge + payment `transaction_data`, verifies the presentation, issues the signed Intent. |
| **Agent** | `packages/agent` | Holds the payment wallet; pays via x402 with the issued Intent. |
| **Merchant** | `packages/merchant` (`mandate-gate.ts`) | Verifies `Payment ⊆ Cart ⊆ Intent` + cap, then settles. **Unchanged** by x401. |

`@proof.com/x401-node` provides only the wire format (challenge, VP Artifact,
PROOF-REQUIRED/PRESENTATION headers, token exchange). It never verifies
credentials and never drives the wallet — we supply both.

---

## 3. The combined flow

```
Phase A — identity + payment authorization (x401 + Proof + transaction_data)
 1. Verifier builds payment transaction_data (payment-mandate v1) from its own
    catalog price, and an x401 challenge with that payment's digest sealed in.
 2. Verifier returns PROOF-REQUIRED { dcql/scope, challenge(nonce), oauth }.
 3. Wallet selectively discloses the requested claims and signs a KB-JWT over
    the nonce → vp_token  (live: Proof hosted redirect; offline: in-browser).
 4. Verifier verifies: challenge (resource/method/expiry) + SD-JWT-VC (issuer
    signature, holder cnf binding, KB nonce, required claims) + payment binding
    (recomputed transaction_data digest == the digest sealed in the challenge).
 5. AuthorizationService maps the disclosed subject → Principal and signs a HAM
    Intent (principal.verifiedVia = "x401-vp", with a credential audit ref).

Phase B — payment (x402 + HAM) — existing code, unchanged
 6. Agent pays /buy via x402 with the Intent; mandate-gate enforces
    Payment ⊆ Cart ⊆ Intent + cumulative cap; the facilitator settles.
```

---

## 4. Selective disclosure (DCQL)

Credentials are **SD-JWT-VC**: every `proof_id_default` claim (`given_name`,
`family_name`, `birth_date`, `email`, `document_number`, `nationality`,
`issuing_country`, `age_over_18`, `age_over_21`) is an independent disclosure.
The verifier's **DCQL query** names exactly which it wants; the wallet reveals
that subset and **withholds the rest** (e.g. disclose `age_over_21` without
revealing `birth_date`). `requiredClaims` on the verifier side fails the
presentation if a required claim was not disclosed.

---

## 5. The 401↔402 join: `transaction_data`

Proof's OID4VP endpoint accepts `transaction_data` of type
`urn:proof:params:vc:transaction-data:payment-mandate:v1` — details the End-User
explicitly authorizes. We carry the agent's payment (amount, merchant, asset,
network, sku) there. The returned presentation is bound to its digest, and we
seal the **same digest into the x401 challenge** (authenticated by the challenge
encryptor). Verification recomputes the digest from the presented payment and
requires a match — so a presentation captured for one payment **cannot be
replayed against a different amount or merchant** (`txDataBound`).

---

## 6. What the verifier proves (and the checks)

| Property | Check |
|---|---|
| Challenge authenticity / freshness | `verifier.verifyChallenge` — verifier id, resource, method, expiry, encryptor-sealed state |
| Genuine credential | Live: `@proof.com/proof-vc-common` `verifyVPToken` verifies the SD-JWT-VC issuer `x5c` chain (ES256) against Proof's committed trust store (`trustRoot`). (The hand-rolled `proofVcVerifier` — chain pinned to a CA fingerprint/root PEM — remains as an offline fallback.) Local mode uses a resolved issuer key instead. |
| Holder actually presented it | KB-JWT verified against the credential's `cnf` key (`holderBound`) |
| Anti-replay | KB-JWT `nonce` == challenge value (`nonceBound`) |
| Right info disclosed | DCQL `requiredClaims` all present |
| Bound to *this* payment | recomputed `transaction_data` digest == sealed digest (`txDataBound`) |

Any failure ⇒ the presentation is rejected and **no Intent is issued**, so x402
never runs.

---

## 7. Seam design (matches the repo doctrine)

`VerifiableCredentialVerifier` is a swappable seam with **three** implementations
behind one interface (like `FacilitatorClient` and `IdentityVerifier`):

| Verifier | Trust source | Used by |
|---|---|---|
| `localVcVerifier` | a pinned self-issuer key (`LocalVcIssuer`) | the offline / self-issued path, tests, CI |
| `proofSdkVcVerifier` | `@proof.com/proof-vc-common` `verifyVPToken`, pinned to Proof's committed trust store via `trustRoot` | the live Proof-hosted path |
| `proofVcVerifier` | hand-rolled x5c chain walk pinned to a Proof CA fingerprint | offline x5c fallback / trust-pin override |

`createVcVerifier({ mode, proof })` selects one (`PROOF_MODE` + `proof.useSdk`).
Mocks implement the real interface, so tests exercise the same verification path
as live.

### The three wallet workflows

The demo exposes a `WALLET_FLOW` selector (switchable live in the UI) over the
same x401 → HAM → x402 spine:

| Workflow | Identity | Per-purchase human? | Drives |
|---|---|---|---|
| **Self-issued** | browser-held local SD-JWT-VC | yes (in-browser consent) | `localVcVerifier` + `LocalWallet` |
| **Proof-hosted** | real Proof wallet | yes (Proof hosted screen) | `proof-vc-common` `getAuthorizationRequestURL` + `verifyVPToken`; the official `<proof-verify-id>` web component (`proof-vc-web`) launches the request with our PAR-built URL |
| **Delegated** (autonomous) | one upfront grant (either of the above) | **no** | a durable, scoped `IntentMandate` the agent spends within |

### Delegated mandate (presigned identity = authorization)

The human makes **one** selective-disclosure presentation that authorizes a
*budget grant* (a `payment-mandate` whose `prompt_summary` is the standing
instruction and whose amount is the cap) instead of a single payment. The
Authorization Service issues **one long-lived** `IntentMandate` (`merchantAllowlist`
+ `allowedCategories` + `maxAmount` + a `MANDATE_TTL` expiry). The agent then
settles **many** purchases over x402 with **no further human approval** — the
signed Intent is the standing authorization. The merchant's existing
`IntentSpendLedger` enforces the **cumulative cap across purchases**, so an
over-budget or out-of-scope buy is denied on its own, with nobody in the loop
(`POST /api/agent/run`; `test/e2e-delegated.test.ts`). This is the up-front
authorization model HAM was designed for — a headless agent can't complete a
human-in-the-loop redirect mid-`/buy`, so the human pre-authorizes a scope once.

**Revocation.** A durable mandate would be unstoppable until expiry, so the issuer
can **revoke** it early: `AuthorizationService.revokeIntent(id)` records it, and the
merchant gate refuses any further spend against that Intent — even though it's still
validly signed, in-scope, under-cap, and unexpired. Revocation is by mandate `id`,
permanent, and checked *before* the cap reservation, so a leaked or compromised
standing mandate is killed at the merchant the moment it's revoked
(`POST /api/mandate/revoke`; `test/e2e-revocation.test.ts`).

The merchant reads status through the `RevocationChecker` seam, selectable via
`REVOCATION_MODE`: an **in-process** `RevocationRegistry` (default), or an **HTTP**
`httpRevocationChecker` against the issuer's status endpoint (OCSP / status-list
style) so issuer and merchant can be separate services. The HTTP path is
**fail-closed** — if the merchant can't confirm "not revoked" (unreachable, timeout,
non-200, ambiguous), the spend is denied. (See ARCHITECTURE.md §8.)

### Orchestrator session model (who may spend a mandate)

The demo orchestrator is **per-client isolated** and **gated**: each browser gets a
signed, HttpOnly `SameSite=Lax` session cookie, and all per-client state (`flow`,
the in-flight x401 attempt, the issued `intent`) lives in that session — so one
client can never see or spend another's mandate. A shared `DEMO_AUTH_TOKEN` gates
every state/spend endpoint (`POST /api/login`, timing-safe compare); it's **open in
local dev** (no token) and **fails closed** when exposed (`NODE_ENV=production` or
`DEMO_REQUIRE_AUTH=true` ⇒ refuse to boot without a token + `DEMO_SESSION_SECRET`),
mirroring the `X401_ENCRYPTOR_KEY` guard. `SameSite=Lax` is the CSRF mitigation.
Tests: `test/e2e-demo-server.test.ts` (isolation), `test/e2e-demo-auth.test.ts`
(gate + fail-closed). Note: the agent wallet is shared infrastructure; isolation of
*authority* holds because each session holds only its own `intent`. The in-memory
session store is single-process (fine for the demo; a real deployment would back it
with a shared store).

---

## 8. Threat model & current limits

| Threat | Defense |
|---|---|
| Agent acts with no human behind it | No valid presentation ⇒ no Intent ⇒ refused. In the **delegated** flow the human still presents once up front; the agent's autonomy is bounded by that signed scope + cap + expiry. |
| Standing mandate leaked / agent compromised | The issuer **revokes** the Intent (`revokeIntent`); the merchant refuses every subsequent spend against it, independent of scope/cap/expiry (`RevocationChecker`). |
| Tampered / forged credential | SD-JWT issuer signature must verify against a trusted key. |
| Stolen presentation replayed | KB-JWT nonce bound to a single-use challenge. |
| Presentation reused for a different payment | `transaction_data` digest binding (`txDataBound`). |
| Over-disclosure | DCQL selective disclosure; wallet reveals only requested claims. |
| A different wallet rides the Intent | Merchant checks `payer == agentWallet` (existing HAM). |

**Limits (sandbox):** the SDK verifier (`proofSdkVcVerifier`) pins to Proof's
committed trust store via `trustRoot` (`development` for the Fairfax sandbox,
`production` for prod) — so the open "pin the actual Root CA" item is resolved for
the live path. The legacy `proofVcVerifier` still pins by SHA-256 fingerprint
(default: Fairfax issuing CA) as an offline fallback. In the **self-issued** and
**proof-hosted** flows the holder presents once per purchase; the **delegated**
flow is exactly the reusable-mandate model — one presentation authorizes many
autonomous purchases within the signed scope/cap/expiry. Note: live Proof also
binds the payment *inside* the holder-signed KB-JWT (`payment_mandate_v1`), which
we surface as `paymentApproved`; our independent challenge-sealed digest binding
is enforced in addition.

---

## 9. Relationship to HAM / AP2 / x402

x401 is an **alternative, richer identity source for HAM**: instead of OIDC →
Intent, it is VC-presentation → Intent, plus a payment binding HAM/AP2 leave
open. Everything downstream of the signed Intent (Cart/Payment scope checks,
cumulative cap, x402 settlement) is unchanged. See
[HAM-PROTOCOL.md](./HAM-PROTOCOL.md).
