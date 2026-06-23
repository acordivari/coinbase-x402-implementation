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
| Genuine credential | SD-JWT-VC issuer signature against a trusted issuer key (`iss`) |
| Holder actually presented it | KB-JWT verified against the credential's `cnf` key (`holderBound`) |
| Anti-replay | KB-JWT `nonce` == challenge value (`nonceBound`) |
| Right info disclosed | DCQL `requiredClaims` all present |
| Bound to *this* payment | recomputed `transaction_data` digest == sealed digest (`txDataBound`) |

Any failure ⇒ the presentation is rejected and **no Intent is issued**, so x402
never runs.

---

## 7. Seam design (matches the repo doctrine)

`VerifiableCredentialVerifier` is a swappable seam with two implementations
behind one interface (like `FacilitatorClient` and `IdentityVerifier`):

| Mode | Issuer | Verifier | Wallet |
|---|---|---|---|
| `local` | `LocalVcIssuer` (self-issued SD-JWT-VC) | `localVcVerifier` (pinned trust key) | `LocalWallet` (in-browser) |
| `live` | Proof | `proofVcVerifier` (Proof issuer trust) | Proof hosted (OID4VP redirect) |

`createVcVerifier({ mode })` selects from `PROOF_MODE`. Mocks implement the real
interface, so tests exercise the same verification path as live.

---

## 8. Threat model & current limits

| Threat | Defense |
|---|---|
| Agent acts with no human behind it | No valid presentation ⇒ no Intent ⇒ refused. |
| Tampered / forged credential | SD-JWT issuer signature must verify against a trusted key. |
| Stolen presentation replayed | KB-JWT nonce bound to a single-use challenge. |
| Presentation reused for a different payment | `transaction_data` digest binding (`txDataBound`). |
| Over-disclosure | DCQL selective disclosure; wallet reveals only requested claims. |
| A different wallet rides the Intent | Merchant checks `payer == agentWallet` (existing HAM). |

**Limits (sandbox):** live issuer-trust resolution is pin-or-well-known (formal
Proof trust list / DIF CTE is an open item); the holder presents once per
purchase (a reusable x401 token-exchange flow is supported by the SDK but not yet
wired); transaction_data binding is enforced at the challenge layer rather than
inside the KB-JWT `transaction_data_hashes` claim.

---

## 9. Relationship to HAM / AP2 / x402

x401 is an **alternative, richer identity source for HAM**: instead of OIDC →
Intent, it is VC-presentation → Intent, plus a payment binding HAM/AP2 leave
open. Everything downstream of the signed Intent (Cart/Payment scope checks,
cumulative cap, x402 settlement) is unchanged. See
[HAM-PROTOCOL.md](./HAM-PROTOCOL.md).
