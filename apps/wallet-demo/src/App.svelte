<script lang="ts">
  import { onMount } from "svelte";
  import { api, usd, short } from "./lib/api";
  import FlowViz from "./lib/FlowViz.svelte";
  import PaymentAuthCard from "./lib/PaymentAuthCard.svelte";
  import MerchantPanel from "./lib/MerchantPanel.svelte";
  import {
    ensureHolderKeys,
    presentInBrowser,
    decodeDisclosed,
    saveCredential,
    loadCredential,
    clearWallet,
    type HeldCredential,
    type HolderKeys,
  } from "./lib/walletClient";
  import { DEMO_HOLDERS } from "@agentic-payments/credentials/browser";

  let me = $state<any>({ mode: "local", claimUniverse: [] });
  let catalog = $state<any[]>([]);
  let orders = $state<any[]>([]);
  let log = $state<{ msg: string; cls: string }[]>([]);

  let keys = $state<HolderKeys | undefined>(undefined);
  let credential = $state<HeldCredential | undefined>(undefined);
  let persona = $state("andrew@example.com");

  let selectedSku = $state<string>("");
  let requested = $state<string[]>(["given_name", "family_name", "email", "age_over_21"]);
  let ttl = $state(600);

  let authSession = $state<any>(undefined);
  let present = $state<any>(undefined); // {disclosed, withheld, missing, vpToken}
  let verification = $state<any>(undefined);
  let intent = $state<any>(undefined);
  let busy = $state(false);
  let pasted = $state("");

  // Live mode: when the redirect_uri is a page we don't control, the user pastes
  // the returned URL (or raw vp_token) here to bring the presentation back.
  function extractVpToken(input: string): string | undefined {
    const s = input.trim();
    if (!s) return undefined;
    if (s.includes("#") || s.includes("vp_token=")) {
      const frag = s.includes("#") ? s.slice(s.indexOf("#") + 1) : s;
      return new URLSearchParams(frag).get("vp_token") ?? undefined;
    }
    return s; // assume a raw token was pasted
  }
  async function submitPasted() {
    const vpToken = extractVpToken(pasted);
    if (!vpToken) return logLine("Couldn't find a vp_token in that input.", "bad");
    pasted = "";
    await onVpToken(vpToken);
  }

  const logLine = (msg: string, cls = "info") => (log = [{ msg, cls }, ...log].slice(0, 60));
  const selectedProduct = $derived(catalog.find((p) => p.sku === selectedSku));
  const heldNames = $derived(credential?.claimNames ?? []);
  const previewDisclose = $derived(requested.filter((c) => heldNames.includes(c)));
  const previewWithheld = $derived(heldNames.filter((c) => !requested.includes(c)));
  const previewMissing = $derived(requested.filter((c) => !heldNames.includes(c)));

  const steps = $derived.by(() => {
    const provisioned = me.mode === "live" || !!credential;
    const settled = orders.some((o) => o.state === "SETTLED");
    const paying = !!intent && !settled;
    const s = (status: any, title: string, sub?: string) => ({ status, title, sub });
    return [
      s(provisioned ? "done" : "active", "Provision wallet", me.mode === "live" ? "Proof-hosted credential" : credential ? "credential held in browser" : "issue a credential"),
      s(authSession ? "done" : provisioned ? "active" : "todo", "Request authorization", "PROOF-REQUIRED + payment transaction_data"),
      s(present ? "done" : authSession ? "active" : "todo", "Present credential", "selective disclosure (DCQL)"),
      s(verification ? (verification.ok ? "done" : "bad") : present ? "active" : "todo", "Verify presentation", "challenge + VC + payment binding"),
      s(intent ? "done" : verification?.ok ? "active" : "todo", "Issue HAM Intent", "bind verified identity → agent scope"),
      s(settled ? "done" : paying ? "active" : "todo", "Pay via x402", "EIP-3009 USDC authorization"),
      s(settled ? "done" : "todo", "Settle on-chain", "facilitator submits the transfer"),
    ];
  });

  onMount(async () => {
    await refreshMe();
    const cat = await api("/api/catalog");
    catalog = cat.products ?? [];
    selectedSku = catalog[0]?.sku ?? "";
    if (me.mode === "local") {
      keys = await ensureHolderKeys();
      credential = loadCredential();
    }
    // Fallback: if Proof redirected the whole tab to the origin with the token in
    // the fragment, complete it here (the /proof/callback page handles the normal case).
    const hp = new URLSearchParams(location.hash.slice(1));
    if (hp.get("vp_token")) { history.replaceState(null, "", "/"); await onVpToken(hp.get("vp_token")!); }
    const cb = localStorage.getItem("x401:callback");
    if (cb) { localStorage.removeItem("x401:callback"); const { vpToken } = JSON.parse(cb); if (vpToken) await onVpToken(vpToken); }
    // The callback page completes the authorization itself, then signals us.
    window.addEventListener("message", (e) => {
      if (e.origin !== location.origin) return;
      if (e.data?.type === "x401:done") { logLine("Proof presentation returned — refreshing…", "ok"); refreshMe(); refreshOrders(); }
      else if (e.data?.type === "x401:vp_token" && e.data.vpToken) onVpToken(e.data.vpToken);
    });
    refreshOrders();
    setInterval(refreshOrders, 2000);
    setInterval(refreshMe, 2500); // reflect verification/intent landed via the callback page
  });

  async function refreshMe() {
    me = await api("/api/me");
    intent = me.intent ?? intent;
    if (me.verification) verification = me.verification;
    if (me.sku) selectedSku = me.sku; // restore the in-flight purchase after a redirect
  }
  async function refreshOrders() {
    const r = await api("/api/orders");
    orders = (r.orders ?? []).sort((a: any, b: any) => b.updatedAt - a.updatedAt);
  }

  function toggleClaim(c: string) {
    requested = requested.includes(c) ? requested.filter((x) => x !== c) : [...requested, c];
  }

  async function provision() {
    busy = true;
    try {
      keys = await ensureHolderKeys();
      const claims = DEMO_HOLDERS[persona];
      const r = await api("/api/wallet/issue", { holderPublicJwk: keys.publicJwk, claims });
      if (r.error) return logLine("Issuance failed: " + r.error, "bad");
      credential = r.credential;
      saveCredential(credential!);
      logLine(`Wallet provisioned: ${persona} (credential held in browser)`, "ok");
    } finally { busy = false; }
  }

  async function startAuthorize() {
    if (!selectedSku) return;
    busy = true; present = undefined; verification = undefined; intent = undefined;
    try {
      authSession = await api("/api/authorize/start", { sku: selectedSku, requestedClaims: requested, ttlSeconds: ttl });
      logLine(`PROOF-REQUIRED issued · ${authSession.requestedClaims.length} claims requested · payment ${usd(authSession.payment.amount)}`, "info");
      if (me.mode === "live") {
        logLine("Opening Proof hosted wallet…", "info");
        const w = window.open(authSession.authorizeUrl, "proof", "width=520,height=760");
        if (!w) { logLine("Popup blocked — redirecting this tab to Proof…", "info"); window.location.href = authSession.authorizeUrl; }
      }
    } finally { busy = false; }
  }

  async function approveLocal() {
    if (!credential || !keys || !authSession) return;
    busy = true;
    try {
      present = await presentInBrowser({
        privateJwk: keys.privateJwk, credential, query: authSession.dcql,
        nonce: authSession.nonce, audience: authSession.audience,
      });
      logLine(`Disclosed [${present.disclosed.join(", ")}] · withheld [${present.withheld.join(", ")}]`, "ok");
      await onVpToken(present.vpToken);
    } finally { busy = false; }
  }

  async function onVpToken(vpToken: string) {
    if (me.mode === "live") {
      const decoded = await decodeDisclosed(vpToken);
      present = { disclosed: decoded.disclosed, withheld: [], missing: [], vpToken, subject: decoded.subject };
      logLine(`Proof returned a presentation disclosing [${decoded.disclosed.join(", ")}]`, "ok");
    }
    const r = await api("/api/authorize/complete", { vpToken });
    verification = r.verification ?? verification;
    if (r.error) { logLine(`Verification rejected: ${r.error}`, "bad"); return; }
    intent = r.intent;
    logLine(`Presentation verified → HAM Intent signed for ${intent?.principal?.email ?? intent?.principal?.sub}`, "ok");
    refreshMe();
  }

  async function pay() {
    if (!intent) return;
    busy = true;
    try {
      logLine(`Agent paying for ${selectedSku} via x402…`, "info");
      const r = await api("/api/buy", { sku: selectedSku });
      if (r.ok) logLine(`✓ ${selectedSku}: ${r.settled?.state ?? "authorized"}${r.settled?.txHash ? " · tx " + short(r.settled.txHash) : ""}`, "ok");
      else logLine(`✗ refused (HTTP ${r.status}): ${JSON.stringify(r.body?.violations ?? r.body?.error)}`, "bad");
      refreshOrders();
    } finally { busy = false; }
  }

  async function reset() {
    await api("/api/reset", {});
    authSession = undefined; present = undefined; verification = undefined; intent = undefined;
    logLine("Session reset.", "info");
    refreshMe();
  }
</script>

<header class="top">
  <div>
    <h1>x401 + x402 — Who authorized this agentic payment?</h1>
    <p>A verified human selectively discloses identity <b>and</b> authorizes the payment in one credential presentation; the agent then settles over x402.</p>
  </div>
  <div class="row">
    <span class="pill">mode <b style="color:var(--acc);margin-left:4px">{me.mode}</b></span>
    <span class="pill">agent <span class="mono">{short(me.agentWallet)}</span></span>
    <button class="ghost" onclick={reset}>Reset</button>
  </div>
</header>

<div class="wrap">
  <div class="grid">
    <!-- LEFT: wallet + authorization -->
    <div class="col">
      <div class="card">
        <h2><span class="step">1</span> Wallet</h2>
        {#if me.mode === "live"}
          <p class="note">Live mode: the credential lives in your <b>Proof</b> wallet. Selective disclosure happens on Proof's hosted flow; we decode the returned presentation to visualize it.</p>
        {:else}
          <div class="row spread">
            <div class="row">
              <span class="mut">Persona</span>
              <select bind:value={persona}>
                {#each Object.keys(DEMO_HOLDERS) as email}<option value={email}>{email}</option>{/each}
              </select>
            </div>
            <button onclick={provision} disabled={busy}>{credential ? "Re-issue" : "Provision wallet"}</button>
          </div>
          {#if credential}
            <div class="divider"></div>
            <div class="row" style="gap:6px">
              {#each credential.claimNames as c}
                <span class="chip-claim" title="held, selectively disclosable">{c}: <b style="margin-left:4px">{String(DEMO_HOLDERS[persona]?.[c] ?? "•")}</b></span>
              {/each}
            </div>
            <p class="note" style="margin:10px 0 0">SD-JWT-VC held in this browser. Holder key bound via <span class="mono">cnf</span>; every claim is independently disclosable.</p>
          {/if}
        {/if}
      </div>

      <div class="card">
        <h2><span class="step">2</span> Choose purchase &amp; what to disclose</h2>
        <div>
          {#each catalog as p}
            <div class="prod {p.sku === selectedSku ? 'sel' : ''}">
              <label class="row" style="gap:8px;cursor:pointer">
                <input type="radio" name="sku" value={p.sku} bind:group={selectedSku} />
                <span><b>{p.name}</b><br /><span class="mut" style="font-size:12px">{p.sku} · {p.category}</span></span>
              </label>
              <span class="pill">${p.priceUsd}</span>
            </div>
          {/each}
        </div>
        <div class="divider"></div>
        <div class="mut" style="margin-bottom:6px">Identity claims to request (DCQL):</div>
        <div class="row" style="gap:6px">
          {#each me.claimUniverse as c}
            <button type="button" class="chip-claim {requested.includes(c) ? 'on' : ''}" onclick={() => toggleClaim(c)}>{c}</button>
          {/each}
        </div>
        <div class="row spread" style="margin-top:12px">
          <div class="row"><span class="mut">TTL</span><input type="number" bind:value={ttl} min="60" style="width:90px" /><span class="mut">sec</span></div>
          <button onclick={startAuthorize} disabled={busy || (me.mode === 'local' && !credential)}>Request authorization</button>
        </div>
      </div>

      {#if authSession}
        <PaymentAuthCard payment={authSession.payment} bound={verification ? verification.txDataBound : undefined} />

        <div class="card fade-in">
          <h2><span class="step">3</span> Consent &amp; selective disclosure</h2>
          {#if me.mode === "local"}
            <div class="mut" style="margin-bottom:6px">The wallet will reveal only:</div>
            <div class="row" style="gap:6px">
              {#each previewDisclose as c}<span class="chip-claim claim-disclosed">{c}</span>{/each}
              {#each previewMissing as c}<span class="chip-claim" style="border-color:var(--warn);color:var(--warn)">{c} (missing)</span>{/each}
            </div>
            {#if previewWithheld.length}
              <div class="mut" style="margin:10px 0 6px">Withheld (held but not shared):</div>
              <div class="row" style="gap:6px">{#each previewWithheld as c}<span class="chip-claim claim-withheld">{c}</span>{/each}</div>
            {/if}
            <button style="margin-top:12px" onclick={approveLocal} disabled={busy || !!present}>Approve &amp; present</button>
          {:else}
            <p class="note">Approve the presentation in the Proof window. If the demo's callback is registered as your redirect URI it returns automatically; otherwise copy the URL Proof lands on (it contains <span class="mono">#vp_token=…</span>) and paste it below.</p>
            <textarea
              bind:value={pasted}
              placeholder="Paste the redirect URL (…#vp_token=…) or the raw vp_token"
              rows="3"
              style="width:100%;margin-top:8px;background:var(--chip);border:1px solid var(--line);color:var(--ink);border-radius:8px;padding:8px;font-family:ui-monospace,monospace;font-size:12px"
            ></textarea>
            <button style="margin-top:8px" onclick={submitPasted} disabled={busy || !pasted.trim()}>Submit presentation</button>
            {#if present}
              <div class="row" style="gap:6px;margin-top:8px">{#each present.disclosed as c}<span class="chip-claim claim-disclosed">{c}</span>{/each}</div>
            {/if}
          {/if}
        </div>
      {/if}

      {#if intent}
        <div class="card fade-in">
          <h2><span class="step">4</span> Pay</h2>
          <p class="note" style="margin:0 0 10px">Identity + payment authorized. The agent now settles <b>{selectedProduct?.name}</b> ({usd(authSession?.payment?.amount)}) over x402 — gated by the signed Intent.</p>
          <button class="alt" onclick={pay} disabled={busy}>Pay {usd(authSession?.payment?.amount)} via x402</button>
        </div>
      {/if}

      <div class="card">
        <h2>Activity</h2>
        <div class="log">
          {#each log as l}<div class={l.cls}>{l.msg}</div>{/each}
          {#if !log.length}<div class="mut">No activity yet.</div>{/if}
        </div>
      </div>
    </div>

    <!-- RIGHT: flow + merchant -->
    <div class="col">
      <div class="card">
        <h2>Protocol flow</h2>
        <FlowViz {steps} />
      </div>
      <MerchantPanel {orders} {intent} {verification} />
    </div>
  </div>
</div>
