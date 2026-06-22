# Runbook: model ↔ endpoint preflight (Tailscale Aperture / LLM gateway guard)

## The incident this prevents

An expensive, high-token `claude-opus-4-8` session was running fine (talking
directly to `api.anthropic.com`). In a *different* session, the
`ANTHROPIC_BASE_URL` was changed to point at a Tailscale **Aperture** proxy on
the tailnet. That proxy enforces Aperture's **default configuration**, whose
Anthropic allowlist only enumerates models **up to `claude-opus-4-7`**:

> `claude-sonnet-4-6`, `claude-haiku-4-5`, `claude-haiku-4-5-20251001`, `claude-opus-4-7`
> — https://tailscale.com/docs/aperture/configuration#default-configuration

The default grant is `"models": "**"`, which sounds permissive but only matches
models that are *configured*. `claude-opus-4-8` is **not** in the default list,
so every 4.8 request through Aperture is rejected — and the in-flight 4.8
session broke.

### Why a change in one session broke another

Two mechanisms, either or both can apply:

1. **Settings hot-reload.** Claude Code reads most settings (including the
   `env` block, where `ANTHROPIC_BASE_URL` lives) **dynamically, without a
   restart**. So editing a shared settings file mid-flight re-points a
   *running* session. (`model` itself is read once at session start — but the
   *endpoint* is not.) Refs:
   - Env vars: https://code.claude.com/docs/en/env-vars.md
   - Settings & precedence: https://code.claude.com/docs/en/settings.md
   - LLM gateway: https://code.claude.com/docs/en/llm-gateway.md
2. **Transparent network routing.** Bringing up the Aperture route (app
   connector / subnet route / MagicDNS override) can pull *all* host traffic to
   `api.anthropic.com` through the tailnet — even sessions that never set a base
   URL. Tailscale uses the CGNAT range `100.64.0.0/10`; if `api.anthropic.com`
   resolves into that range, your Anthropic traffic is tailnet-pinned.

## The setting you couldn't find in the public docs

`ANTHROPIC_BASE_URL` is the documented override. It can be set either as a
shell env var **or** inside a settings file under an `env` key:

```jsonc
// .claude/settings.json (or settings.local.json, or ~/.claude/settings.json)
{ "env": { "ANTHROPIC_BASE_URL": "https://aperture.your-tailnet.ts.net" } }
```

Precedence (high → low): **shell env** → `~/.claude/settings.local.json` →
project `.claude/settings.local.json` → project `.claude/settings.json` →
`~/.claude/settings.json`. Auth to a gateway uses `ANTHROPIC_AUTH_TOKEN`
(`Authorization: Bearer`), falling back to `ANTHROPIC_API_KEY` (`x-api-key`);
OAuth is disabled once a custom base URL is set. Docs:
https://code.claude.com/docs/en/llm-gateway.md and
https://code.claude.com/docs/en/settings.md

## The guard: `scripts/preflight-model.sh`

Run it before kicking off any costly run. It:

1. Resolves the **target model** (`$1` → `ANTHROPIC_MODEL` →
   `ANTHROPIC_DEFAULT_OPUS_MODEL` → `claude-opus-4-8`), stripping a `[1m]`-style
   context tag down to the allowlist key.
2. Resolves the **effective** `ANTHROPIC_BASE_URL` across shell env + all
   settings files using Claude Code's precedence, and reports the source.
3. Checks the **network route** — warns if `api.anthropic.com` resolves into the
   Tailscale CGNAT range (catches transparent routing with no base URL set).
4. If an endpoint other than `api.anthropic.com` is in effect, **probes** it:
   `GET /v1/models` first (free, no tokens); falls back to a **1-token**
   `POST /v1/messages` if the gateway doesn't expose a model list.

Exit codes: `0` OK · `1` BLOCKED (endpoint rejects the model — the bug) · `2`
CONFIG (unreachable / unverifiable).

```bash
scripts/preflight-model.sh                 # checks claude-opus-4-8 by default
scripts/preflight-model.sh claude-opus-4-8
```

## Optional: run it automatically at every session start

`SessionStart` fires on `startup | resume | clear | compact`. Wire the wrapper
(`.claude/hooks/session-preflight.sh`) so a bad endpoint is impossible to miss.
It is **non-blocking** — it warns loudly and injects a note for the assistant,
but never aborts the session.

```jsonc
// add to .claude/settings.json (project) or ~/.claude/settings.json (global)
{
  "hooks": {
    "SessionStart": [
      { "matcher": "startup|resume",
        "hooks": [ { "type": "command",
          "command": "${CLAUDE_PROJECT_DIR}/.claude/hooks/session-preflight.sh" } ] }
    ]
  }
}
```

## Operational rules (the cheap fixes)

- **Don't edit a shared `ANTHROPIC_BASE_URL` while an expensive session is
  live.** It hot-reloads into the running session. Finish or checkpoint first.
- **Scope the override narrowly.** Prefer a per-terminal `export
  ANTHROPIC_BASE_URL=...` (or `direnv`) over the global
  `~/.claude/settings.json` `env` block, so one experiment can't leak into every
  session on the machine.
- **If you must use the tailnet gateway with 4.8**, update the Aperture config
  to add `claude-opus-4-8` to the Anthropic provider's model list *before*
  pointing sessions at it — then re-run the preflight to confirm.
- **Keep the most expensive runs direct** (`api.anthropic.com`) unless the
  gateway is verified for the exact model id.
