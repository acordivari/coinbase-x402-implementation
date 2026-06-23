/**
 * Mock-VeryGood-RX product catalog. VeryGood-RX has no x402 API, so this is a simulated
 * storefront — but the prices flow through the real payment + authorization
 * rails. Categories line up with the mandate `allowedCategories` so the HAM
 * scope checks (Phase 2) have something meaningful to gate on.
 */
import { dollarsToAtomic } from "@agentic-payments/shared";

export interface Product {
  sku: string;
  name: string;
  category: string;
  priceUsd: string;
}

export const CATALOG: readonly Product[] = [
  { sku: "allergy-relief-24", name: "Allergy Relief 24-hr (30ct)", category: "otc-medicine", priceUsd: "1.50" },
  { sku: "ibuprofen-200", name: "Ibuprofen 200mg (50ct)", category: "otc-medicine", priceUsd: "0.75" },
  { sku: "vitamin-d3-2000", name: "Vitamin D3 2000 IU (90ct)", category: "vitamins", priceUsd: "2.25" },
  { sku: "bandages-assorted", name: "Adhesive Bandages (40ct)", category: "first-aid", priceUsd: "0.50" },
  { sku: "toothpaste-mint", name: "Mint Toothpaste (4oz)", category: "personal-care", priceUsd: "1.00" },
];

const BY_SKU = new Map(CATALOG.map((p) => [p.sku, p]));

export function findProduct(sku: string): Product | undefined {
  return BY_SKU.get(sku);
}

/** Price of a product in atomic USDC units (throws on unknown sku). */
export function productPriceAtomic(sku: string): bigint {
  const p = BY_SKU.get(sku);
  if (!p) throw new Error(`Unknown sku: ${sku}`);
  return dollarsToAtomic(p.priceUsd);
}
