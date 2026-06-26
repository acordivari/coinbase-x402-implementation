# Agentic Payments Sandbox — x402 + Human-Identity Authorization

A working, testnet-only sandbox for **agent-initiated payments** over the
[x402 protocol](https://docs.cdp.coinbase.com/x402/welcome), with a research
layer that answers the question underneath agentic commerce: **which human
authorized this agent to spend, and within what scope?** Companies like Walmart, Tesla, and CVS are prioritizing infrastructure to expand agentic commerce. The sample flow below simulates the purchase of allergy medication from CVS. Funds for validation can be generated through [a faucet.](https://faucet.circle.com/)

> **No real funds, no real wallet.** Everything runs on **Base Sepolia testnet**
> against the free facilitator (`https://x402.org/facilitator`), funded with
> faucet test USDC. The agent signs with a headless **Coinbase CDP Server
> Wallet** (or a throwaway viem key) — your MetaMask is never connected.

## 🏁 Milestone — first live settlement (2026-06-20)

The agent completed its first **real, on-chain x402 payment** on Base Sepolia:
the agent received an HTTP `402`, signed an EIP-3009 USDC authorization, and the
live facilitator submitted the transfer — gasless for the agent. The order ledger
walked the full state machine `CREATED → QUOTED → AUTHORIZED → SETTLING → SETTLED`.

| | |
|---|---|
| **Item** | Allergy Relief 24-hr — **1.5 USDC** |
| **Tx** | [`0x7f23b8a5…43ab9e`](https://sepolia.basescan.org/tx/0x7f23b8a593d831fafd287389609f5655bbd1790dd199f78caeec38696243ab9e) |
| **From → To** | agent `0x57dfD786…092aB4` → merchant `0xCb6700f8…406bAe` |
| **Network** | Base Sepolia (`eip155:84532`), block `43124612` |
| **Path** | local viem signer + live `x402.org` facilitator (mandate enforcement off for this payment-rail run) |

Reproduce: `npm run setup:local` → fund the printed address → `npm run merchant`
+ `npm run agent allergy-relief-24`. _Next live milestone: the same settlement
gated by a signed Human Authorization Mandate._

## Docs

- **[Architecture & Decisions](docs/ARCHITECTURE.md)** — the product-owner's
  "what & why": problem, concepts, decision log, safety guarantees.
- **[HAM Protocol Spec](docs/HAM-PROTOCOL.md)** — the Human Authorization Mandate
  data model, verification rules, and threat model.
- **[x401 + Proof VC Authorization](docs/X401-PROTOCOL.md)** — combining x401
  identity proof with x402 payment: selective-disclosure verifiable credentials
  (DCQL) bound to the specific payment via `transaction_data`.

## x401 wallet demo — who authorized this agentic payment?

```bash
npm run demo           # PROOF_MODE=local (offline): build web + boot orchestrator
npm run demo:web       # in another shell for live-reload dev (Vite on :5173)
# then open http://localhost:4040
```

A browser wallet (Vite + Svelte) shows the whole handshake on screen: the human
selectively discloses identity claims via a **DCQL** query **and** authorizes the
exact payment (`transaction_data`) in one SD-JWT-VC presentation; the verifier
checks the credential + nonce + payment binding, issues a signed HAM Intent, and
the agent settles over x402.

### Three wallet workflows (`WALLET_FLOW`, switchable live in the UI)

1. **Self-issued** — browser-held local SD-JWT-VC, selective disclosure in-browser,
   you approve each purchase. Fully offline (`PROOF_MODE=local`).
2. **Proof-hosted** — the real Proof hosted presentation, driven by the official
   **`@proof.com/proof-vc-common`** SDK (`getAuthorizationRequestURL` + PAR +
   `verifyVPToken`, pinned to Proof's trust store via `trustRoot`) with Proof's
   **`<proof-verify-id>`** web component (`@proof.com/proof-vc-web`). Set
   `PROOF_CLIENT_ID`/`PROOF_CLIENT_SECRET`, `PROOF_LOGIN_HINT`, `PROOF_ENVIRONMENT`.
3. **Delegated (autonomous)** — the headline path: the human presents **once** to
   sign a durable, scoped **mandate** (allowlist + budget cap + expiry); the agent
   then buys **many** times over x402 with **no per-purchase approval** — the
   presigned identity is the standing authorization. The merchant's cumulative-cap
   ledger denies an over-budget buy on its own.

```bash
# the autonomous (delegated-mandate) demo, fully offline:
WALLET_FLOW=delegated PROOF_MODE=local FACILITATOR_MODE=mock npm run demo
```

## Why TypeScript

The entire official x402 v2 stack (`@x402/express`, `@x402/evm`, `@x402/fetch`,
the facilitator, AgentKit, the reference agents) is TypeScript-first. This repo
targets the **`@x402/*` v2 packages (2.16.x)**.

## Architecture

A DRY npm-workspaces monorepo. The shared core is defined once and imported by
every package, so payment shapes, validation, and the order state machine can
never drift between agent and merchant.

```
packages/
  shared/     # DRY core: constants, money math, Zod wire schemas (x402 v2),
              # order state machine, mandate (HAM) model + scope validators,
              # payment-parameter validators, Signer interface
  merchant/   # "mock-CVS" storefront (seller)
              #   order-store     — state-machine-guarded order ledger + idempotency
              #   facilitator/    — FacilitatorClient seam:
              #       mock.ts      — offline facilitator (synthetic settlement)
              #       resilient.ts — retry + per-nonce idempotency + transaction lock
  agent/      # headless buyer agent (CDP Server Wallet -> x402 client)
  identity/   # OIDC verifier (local + Auth0) + HAM signing/verification
  credentials/# x401 + Proof verifiable-credentials seam:
              #   SD-JWT-VC issue/hold/present (selective disclosure) + DCQL,
              #   transaction_data payment binding, VerifiableCredentialVerifier
              #   (local | proof), and @proof.com/x401-node wire wrappers
apps/
  console/    # original one-command demo: buyer + merchant consoles (OIDC + HAM)
  wallet-demo/# Vite + Svelte x401 wallet demo (VC presentation -> HAM -> x402)
```

## Demo console

```bash
npm run console   # then open http://localhost:4040
```

Boots the mock-CVS merchant in-process with mandate enforcement, the local OIDC
issuer, and the headless agent. In the browser: sign in (OIDC) → authorize the
agent by signing an Intent (cap + categories + expiry) → shop. In-scope buys
settle; out-of-scope buys are refused with the reason. The merchant panel shows
live orders with their state-machine status and settlement tx.

### Safety guarantees (validated by tests)

- **Payment-parameter validation** — independent defense-in-depth on the signed
  EIP-3009 authorization (asset allowlist, exact amount, recipient, time window).
- **Order state machine** — `CREATED → QUOTED → AUTHORIZED → SETTLING → SETTLED
  → REFUNDED` (plus `FAILED`/`EXPIRED`); illegal transitions throw, so state can
  never corrupt.
- **Settlement resilience** (`ResilientFacilitatorClient`, the single settlement
  seam): transient failures retry with backoff; **terminal failures never
  retry**; settlement is **idempotent per EIP-3009 nonce** and **lock-coalesced**
  so a retry storm can't double-charge.

### Human Authorization Mandate (HAM)

The protocol contribution, modeled on Google AP2's Intent → Cart → Payment
mandate chain but with the authorizing human's **identity bound into the
Intent**. Scope checks prove `Payment ⊆ Cart ⊆ Intent` (spend cap, merchant
allowlist, item categories, expiry). See `packages/shared/src/mandates.ts`.

### x401 identity authorization — verifiable credentials + DCQL

The newest layer answers *who authorized this* with a **verifiable credential**
instead of just an OIDC login. It combines the **x401** identity-proof protocol
with x402 payment so a verified human, in a **single credential presentation**,
both **selectively discloses** identity (driven by a **DCQL** query) **and**
**authorizes the specific payment** (Proof's `transaction_data` / `payment-mandate`).
The disclosed identity becomes the HAM principal; the merchant's x402 paywall and
settlement are unchanged.

- **New seam** (`packages/credentials`): a `VerifiableCredentialVerifier` with three
  implementations behind one interface — `localVcVerifier` (self-issued SD-JWT-VC,
  offline/CI), `proofSdkVcVerifier` (live Proof via the official
  `@proof.com/proof-vc-common` SDK), and `proofVcVerifier` (hand-rolled x5c fallback).
  Mirrors the facilitator/identity seams; selected by `PROOF_MODE` + `proof.useSdk`.
- **Three wallet workflows** (`WALLET_FLOW`): self-issued, Proof-hosted (SDK +
  `<proof-verify-id>` web component), and **delegated** — a presigned, durable,
  scoped mandate the agent spends autonomously with no per-purchase approval.
- **Selective disclosure (DCQL):** credentials are SD-JWT-VC; the verifier names the
  claims it wants and the wallet reveals only those — e.g. disclose `age_over_21`
  without revealing `birth_date`.
- **Payment binding (the 401↔402 join):** the agent's payment is sealed into the
  x401 challenge, and (live) Proof binds the `payment-mandate` inside the
  holder-signed key-binding JWT — cryptographic proof the human approved *this*
  payment, not just "some payment".
- **Issuer trust:** Proof signs with an ES256 **x5c** certificate chain; the live SDK
  verifier pins it to Proof's committed trust store via `trustRoot`
  (`development`/`production`). The fallback verifier pins by CA fingerprint/root PEM.

Flow: `PROOF-REQUIRED (DCQL + payment) → wallet presentation (vp_token) → verify
(credential + holder + nonce + payment) → signed HAM Intent → x402 settlement`. The
identity source for HAM thus becomes swappable: **OIDC → Intent** *or*
**VC presentation → Intent**, with the payment-rail unchanged. See the
[x401 protocol notes](docs/X401-PROTOCOL.md) and run `npm run demo`.

## Develop

```bash
npm install
npm test          # vitest — 99+ tests across shared, merchant, identity, credentials
npm run typecheck # tsc --noEmit, strict
```

## Live Base Sepolia path

All free; testnet only. The offline demo/tests need none of this
(`FACILITATOR_MODE=mock`).

1. **CDP API key** — create at the Coinbase Developer Platform portal, put
   `CDP_API_KEY_ID`, `CDP_API_KEY_SECRET`, `CDP_WALLET_SECRET` in `.env`.
2. **Set up wallets + faucet** (turnkey):
   ```bash
   npm run setup:live
   ```
   Creates the agent + merchant CDP Server Wallets, pulls testnet USDC from the
   CDP faucet, and prints the `MERCHANT_PAY_TO` + the exact run commands. (No ETH
   needed — settlement is gasless EIP-3009; the facilitator submits.)
3. **Run live:** `FACILITATOR_MODE=http WALLET_MODE=cdp` for the merchant +
   agent, as printed by the setup script. Track wallets on
   `https://sepolia.basescan.org`.
