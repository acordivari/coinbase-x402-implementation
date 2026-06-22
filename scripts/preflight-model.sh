#!/usr/bin/env bash
#
# preflight-model.sh — verify the endpoint you're about to spend tokens against
# actually accepts the model you intend to run.
#
# Why this exists: pointing ANTHROPIC_BASE_URL at an LLM gateway (e.g. a
# Tailscale Aperture proxy on your tailnet) silently constrains which models
# you can call. Aperture's *default* configuration only enumerates Anthropic
# models up to `claude-opus-4-7`. Any `claude-opus-4-8` request that flows
# through it is rejected — which can break an in-flight, expensive session the
# moment the route or the base URL changes. Run this BEFORE starting a costly
# run, and/or wire it as a SessionStart hook (see docs/RUNBOOK-model-endpoint-preflight.md).
#
# Exit codes:
#   0  OK      — effective endpoint accepts the target model
#   1  BLOCKED — endpoint reachable but rejects the target model (the bug we guard against)
#   2  CONFIG  — could not determine config / endpoint unreachable / probe inconclusive
#
# Usage:
#   scripts/preflight-model.sh [MODEL]
#   MODEL defaults to $ANTHROPIC_MODEL, then $ANTHROPIC_DEFAULT_OPUS_MODEL, then claude-opus-4-8
#
# Honors: ANTHROPIC_BASE_URL, ANTHROPIC_AUTH_TOKEN, ANTHROPIC_API_KEY,
#         ANTHROPIC_MODEL, ANTHROPIC_DEFAULT_OPUS_MODEL
set -uo pipefail

# ---- pretty output ---------------------------------------------------------
if [ -t 1 ]; then
  R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; B=$'\033[34m'; DIM=$'\033[2m'; BOLD=$'\033[1m'; X=$'\033[0m'
else
  R=""; G=""; Y=""; B=""; DIM=""; BOLD=""; X=""
fi
say()  { printf '%s\n' "$*"; }
ok()   { printf '%s✓%s %s\n' "$G" "$X" "$*"; }
warn() { printf '%s!%s %s\n' "$Y" "$X" "$*"; }
bad()  { printf '%s✗%s %s\n' "$R" "$X" "$*"; }
hdr()  { printf '\n%s%s%s\n' "$BOLD" "$*" "$X"; }

# ---- 0. resolve target model ----------------------------------------------
MODEL="${1:-${ANTHROPIC_MODEL:-${ANTHROPIC_DEFAULT_OPUS_MODEL:-claude-opus-4-8}}}"
# Strip a trailing context-window tag like `[1m]`; gateways allowlist the base id.
BASE_MODEL="${MODEL%%[*}"

hdr "Model endpoint preflight"
say "${DIM}target model:${X} ${BOLD}${MODEL}${X}${DIM}  (allowlist match key: ${BASE_MODEL})${X}"

# ---- 1. resolve EFFECTIVE base URL (mirrors Claude Code precedence) --------
# Precedence (high→low): shell env > ~/.claude/settings.local.json >
# .claude/settings.local.json > .claude/settings.json > ~/.claude/settings.json
read_setting() {  # $1 = file; prints env.ANTHROPIC_BASE_URL if present
  [ -f "$1" ] || return 0
  if command -v jq >/dev/null 2>&1; then
    jq -r '.env.ANTHROPIC_BASE_URL // empty' "$1" 2>/dev/null
  else
    # best-effort grep fallback (no jq)
    grep -oE '"ANTHROPIC_BASE_URL"[[:space:]]*:[[:space:]]*"[^"]*"' "$1" 2>/dev/null \
      | sed -E 's/.*:[[:space:]]*"([^"]*)"/\1/' | head -n1
  fi
}

PROJ_DIR="${CLAUDE_PROJECT_DIR:-$(pwd)}"
SRC=""
BASE_URL=""
if [ -n "${ANTHROPIC_BASE_URL:-}" ]; then
  BASE_URL="$ANTHROPIC_BASE_URL"; SRC="shell env"
else
  for f in \
    "$HOME/.claude/settings.local.json:user settings.local.json" \
    "$PROJ_DIR/.claude/settings.local.json:project settings.local.json" \
    "$PROJ_DIR/.claude/settings.json:project settings.json" \
    "$HOME/.claude/settings.json:user settings.json"; do
    path="${f%%:*}"; label="${f#*:}"
    v="$(read_setting "$path")"
    if [ -n "$v" ]; then BASE_URL="$v"; SRC="$label ($path)"; break; fi
  done
fi

# ---- 2. network-route sanity: is api.anthropic.com pinned into the tailnet? -
# Catches the *transparent* failure mode where a route change reaches the API
# host even though no base URL is configured. Tailscale uses CGNAT 100.64.0.0/10.
hdr "Network route"
RESOLVER=""
ANTH_IP=""
if command -v dig >/dev/null 2>&1; then RESOLVER="dig"; ANTH_IP="$(dig +short api.anthropic.com A | grep -E '^[0-9]' | head -n1)"
elif command -v host >/dev/null 2>&1; then RESOLVER="host"; ANTH_IP="$(host api.anthropic.com 2>/dev/null | awk '/has address/{print $4; exit}')"; fi
if [ -n "$ANTH_IP" ]; then
  case "$ANTH_IP" in
    100.6[4-9].*|100.[7-9][0-9].*|100.1[0-1][0-9].*|100.12[0-7].*)
      warn "api.anthropic.com → ${BOLD}${ANTH_IP}${X} is in the Tailscale CGNAT range (100.64.0.0/10)."
      warn "Your Anthropic traffic appears to be routed THROUGH the tailnet/Aperture even without a base URL override." ;;
    *) ok "api.anthropic.com → ${ANTH_IP} (public route, not tailnet-pinned)";;
  esac
else
  warn "Could not resolve api.anthropic.com (no dig/host, or offline)."
fi

# ---- 3. direct-to-Anthropic short-circuit ---------------------------------
hdr "Effective endpoint"
norm="${BASE_URL%/}"
if [ -z "$norm" ] || [ "$norm" = "https://api.anthropic.com" ] || [ "$norm" = "http://api.anthropic.com" ]; then
  ok "ANTHROPIC_BASE_URL is ${BOLD}unset / default${X} (api.anthropic.com)."
  say "${DIM}Talking straight to Anthropic; GA models including ${BASE_MODEL} are available.${X}"
  # Still surface the tailnet warning as a non-fatal caution.
  exit 0
fi
warn "ANTHROPIC_BASE_URL = ${BOLD}${norm}${X}"
say  "${DIM}source: ${SRC}${X}"
say  "${DIM}You are NOT talking to api.anthropic.com directly — a gateway controls which models are allowed.${X}"

# ---- 4. auth header for the probe -----------------------------------------
AUTH=()
if [ -n "${ANTHROPIC_AUTH_TOKEN:-}" ]; then AUTH=(-H "Authorization: Bearer ${ANTHROPIC_AUTH_TOKEN}")
elif [ -n "${ANTHROPIC_API_KEY:-}" ]; then AUTH=(-H "x-api-key: ${ANTHROPIC_API_KEY}")
fi  # else: rely on network identity (Tailscale ACLs / Aperture), no header

# NB: ${AUTH[@]+...} guards empty-array expansion under `set -u` on bash 3.2 (macOS default).
CURL=(curl -sS --max-time 15 -H "anthropic-version: 2023-06-01" ${AUTH[@]+"${AUTH[@]}"})

# ---- 5a. cheap probe: GET /v1/models (no inference, no tokens) -------------
hdr "Probing ${norm}"
models_body="$("${CURL[@]}" "${norm}/v1/models" 2>/dev/null)"
if [ -n "$models_body" ] && printf '%s' "$models_body" | grep -q '"data"'; then
  if printf '%s' "$models_body" | grep -q "\"${BASE_MODEL}\""; then
    ok "/v1/models lists ${BOLD}${BASE_MODEL}${X} — endpoint allows your target model."
    exit 0
  else
    bad "/v1/models is reachable but does NOT list ${BOLD}${BASE_MODEL}${X}."
    say "${DIM}Models this gateway advertises:${X}"
    if command -v jq >/dev/null 2>&1; then
      printf '%s' "$models_body" | jq -r '.data[].id' 2>/dev/null | sed 's/^/    /'
    else
      printf '%s' "$models_body" | grep -oE '"id":"[^"]*"' | sed -E 's/"id":"([^"]*)"/    \1/'
    fi
    bad "This is the Aperture-default-config failure mode. Fix the gateway allowlist or run direct."
    exit 1
  fi
fi
warn "/v1/models did not return a usable list (gateway may not expose it). Falling back to a 1-token probe."

# ---- 5b. fallback: minimal /v1/messages probe (1 output token) ------------
req="$(printf '{"model":"%s","max_tokens":1,"messages":[{"role":"user","content":"."}]}' "$BASE_MODEL")"
resp="$("${CURL[@]}" -w $'\n%{http_code}' -H "content-type: application/json" \
        -d "$req" "${norm}/v1/messages" 2>/dev/null)"
code="${resp##*$'\n'}"
body="${resp%$'\n'*}"

case "$code" in
  200)
    ok "1-token probe accepted ${BOLD}${BASE_MODEL}${X} (HTTP 200) — safe to run."
    exit 0 ;;
  400|403|404|422)
    if printf '%s' "$body" | grep -qiE 'model|not.*(found|allow|permit|support)'; then
      bad "Gateway rejected ${BOLD}${BASE_MODEL}${X} (HTTP ${code})."
      printf '%s\n' "${DIM}${body}${X}" | head -c 600; echo
      bad "Endpoint does not permit this model. Do NOT start an expensive ${BASE_MODEL} session here."
      exit 1
    fi
    warn "HTTP ${code} but not clearly a model-allowlist error:"
    printf '%s\n' "${DIM}${body}${X}" | head -c 600; echo
    exit 2 ;;
  401)
    warn "HTTP 401 (auth). Probe could not authenticate — set ANTHROPIC_AUTH_TOKEN / ANTHROPIC_API_KEY, or check tailnet ACLs. Model allowance UNVERIFIED."
    exit 2 ;;
  000|"")
    bad "Could not reach ${norm} (timeout / DNS / TLS). Endpoint unreachable."
    exit 2 ;;
  *)
    warn "Unexpected HTTP ${code}; model allowance UNVERIFIED:"
    printf '%s\n' "${DIM}${body}${X}" | head -c 600; echo
    exit 2 ;;
esac
