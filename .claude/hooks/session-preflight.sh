#!/usr/bin/env bash
#
# SessionStart hook wrapper around scripts/preflight-model.sh.
# Surfaces a loud warning (and injects context for Claude) when the effective
# endpoint won't accept the model you're about to run. Non-blocking by design:
# it never aborts session start, it just makes the misconfig impossible to miss.
#
# Register in settings.json — see docs/RUNBOOK-model-endpoint-preflight.md.
set -uo pipefail
DIR="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
out="$("$DIR/scripts/preflight-model.sh" 2>&1)"; rc=$?

if [ "$rc" -eq 1 ]; then
  # BLOCKED — endpoint rejects the target model. Warn hard on stderr...
  printf '%s\n' "$out" >&2
  printf '\n⛔ PREFLIGHT BLOCKED: this endpoint will reject your model. Fix before spending tokens.\n' >&2
  # ...and inject a note into the session so the assistant is aware too.
  printf '{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"PREFLIGHT WARNING: the effective ANTHROPIC_BASE_URL gateway rejects the target model (likely Tailscale Aperture default config, which only allowlists up to claude-opus-4-7). Expensive runs on claude-opus-4-8 will fail through this endpoint."}}\n'
elif [ "$rc" -eq 2 ]; then
  printf '%s\n' "$out" >&2
  printf '\n⚠ PREFLIGHT INCONCLUSIVE: could not verify the endpoint accepts your model.\n' >&2
fi
# rc 0 → silent success. Always exit 0 so we never block session start.
exit 0
