<script lang="ts">
  type Step = { title: string; sub?: string; status: "todo" | "active" | "done" | "bad" };
  let { steps }: { steps: Step[] } = $props();
</script>

<div class="flow">
  {#each steps as s, i}
    <div class="fstep {s.status}">
      <div class="dotcol">
        <div class="dot"></div>
        {#if i < steps.length - 1}<div class="line"></div>{/if}
      </div>
      <div class="body">
        <div class="title">
          {s.title}
          {#if s.status === "done"}<span class="badge b-ok" style="margin-left:6px">✓</span>{/if}
          {#if s.status === "bad"}<span class="badge b-bad" style="margin-left:6px">✗</span>{/if}
        </div>
        {#if s.sub}<div class="sub">{s.sub}</div>{/if}
      </div>
    </div>
  {/each}
</div>
