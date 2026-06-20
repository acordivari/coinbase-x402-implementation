/**
 * One clock for the whole system. Mandates, the gate, and the order ledger all
 * default to this so there is a single place to reason about (and stub) time,
 * rather than each module re-deriving `Math.floor(Date.now() / 1000)`.
 */
export const nowSeconds = (): number => Math.floor(Date.now() / 1000);
