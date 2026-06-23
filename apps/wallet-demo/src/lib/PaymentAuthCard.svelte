<script lang="ts">
  import { usd, short } from "./api";
  let { payment, bound }: { payment: any; bound?: boolean | undefined } = $props();
</script>

<div class="card fade-in" style="border-color:rgba(138,107,255,.45)">
  <h2>
    <span class="step" style="background:var(--acc2)">transaction_data</span>
    the payment the human authorizes
    {#if bound === true}<span class="badge b-ok" style="margin-left:auto">bound ✓</span>{/if}
    {#if bound === false}<span class="badge b-bad" style="margin-left:auto">unbound ✗</span>{/if}
  </h2>
  {#if payment}
    <div class="kv">
      <span class="k">Amount</span><span><b>{payment.amountUsd ? "$" + payment.amountUsd : usd(payment.amount)}</b> <span class="mut">USDC</span></span>
      <span class="k">Merchant</span><span class="mono">{short(payment.merchant)}</span>
      <span class="k">Item</span><span>{payment.description ?? payment.sku ?? "—"}</span>
      <span class="k">Network</span><span class="mono">{payment.network ?? "—"}</span>
    </div>
    <p class="note" style="margin:10px 0 0">
      This payment-mandate is sealed into the x401 challenge. The credential
      presentation is cryptographically bound to it — proving the human approved
      <b>this exact payment</b>, not just "some payment".
    </p>
  {:else}
    <p class="mut">No payment selected yet.</p>
  {/if}
</div>
