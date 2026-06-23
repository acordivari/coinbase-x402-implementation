/** Thin JSON client for the orchestrator. The browser only talks to us. */
export async function api<T = any>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(
    path,
    body
      ? { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }
      : {},
  );
  return res.json() as Promise<T>;
}

export const usd = (atomic: string | number | undefined) =>
  "$" + (Number(atomic || 0) / 1e6).toFixed(2);
export const short = (s?: string) => (s ? s.slice(0, 6) + "…" + s.slice(-4) : "—");
