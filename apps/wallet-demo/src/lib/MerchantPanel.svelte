<script lang="ts">
  import { usd, short } from "./api";
  let { orders, intent, verification }: { orders: any[]; intent: any; verification: any } = $props();

  const stateClass = (s: string) =>
    s === "SETTLED" ? "b-ok" : s === "FAILED" || s === "EXPIRED" ? "b-bad" : "b-warn";
</script>

<div class="card">
  <h2>Mock-VeryGood-RX merchant · live orders</h2>
  <table>
    <thead><tr><th>Order</th><th>Item</th><th>USDC</th><th>State</th><th>Tx</th></tr></thead>
    <tbody>
      {#if orders?.length}
        {#each orders as o}
          <tr>
            <td class="mono">{(o.id ?? "").replace("ord_0x", "0x").slice(0, 10)}…</td>
            <td>{o.sku}</td>
            <td>{usd(o.amount)}</td>
            <td><span class="badge {stateClass(o.state)}">{o.state}</span></td>
            <td class="mono">{short(o.txHash)}</td>
          </tr>
        {/each}
      {:else}
        <tr><td colspan="5" class="mut">No orders yet.</td></tr>
      {/if}
    </tbody>
  </table>
</div>

{#if verification}
  <div class="card fade-in">
    <h2>Verifier · what was proven</h2>
    <div class="row" style="gap:6px;margin-bottom:10px">
      <span class="badge {verification.challengeOk ? 'b-ok' : 'b-bad'}">challenge {verification.challengeOk ? "ok" : "✗"}</span>
      <span class="badge {verification.nonceBound ? 'b-ok' : 'b-bad'}">nonce bound</span>
      <span class="badge {verification.holderBound ? 'b-ok' : 'b-bad'}">holder bound</span>
      <span class="badge {verification.txDataBound ? 'b-ok' : 'b-bad'}">payment bound</span>
    </div>
    <div class="kv">
      <span class="k">Issuer</span><span class="mono">{verification.issuer ?? "—"}</span>
      <span class="k">Disclosed</span>
      <span>
        {#each verification.disclosed ?? [] as c}<span class="chip-claim claim-disclosed" style="margin:2px">{c}</span>{/each}
        {#if !(verification.disclosed ?? []).length}<span class="mut">none</span>{/if}
      </span>
    </div>
    {#if verification.subject && Object.keys(verification.subject).length}
      <div class="divider"></div>
      <div class="kv">
        {#each Object.entries(verification.subject) as [k, v]}
          <span class="k">{k}</span><span><b>{String(v)}</b></span>
        {/each}
      </div>
    {/if}
    {#if !verification.ok && verification.violations?.length}
      <div class="divider"></div>
      {#each verification.violations as v}<div class="badge b-bad" style="display:block;margin:3px 0">{v}</div>{/each}
    {/if}
  </div>
{/if}

{#if intent}
  <div class="card fade-in">
    <h2>HAM · signed Intent mandate</h2>
    <div class="kv">
      <span class="k">Principal</span>
      <span>
        <b>{intent.principal?.email ?? intent.principal?.sub}</b>
        <span class="badge b-mut" style="margin-left:6px">{intent.principal?.verifiedVia ?? "?"}</span>
      </span>
      <span class="k">Bound wallet</span><span class="mono">{short(intent.agentWallet)}</span>
      <span class="k">Cap</span><span><b>{usd(intent.scope?.maxAmount)}</b></span>
      <span class="k">Categories</span><span>{(intent.scope?.allowedCategories ?? []).join(", ")}</span>
      <span class="k">Signed</span><span>{intent.signed ? "EdDSA ✓" : "no"}</span>
    </div>
    {#if intent.principal?.credential}
      <p class="note" style="margin:10px 0 0">
        Identity backed by credential <span class="mono">{intent.principal.credential.id}</span>
        from <span class="mono">{short(intent.principal.credential.issuer)}</span>,
        disclosing only [{(intent.principal.credential.claimsDisclosed ?? []).join(", ")}].
      </p>
    {/if}
  </div>
{/if}
