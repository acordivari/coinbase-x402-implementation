/**
 * Browser-safe subset of the credentials seam. The main barrel (`.`) pulls in
 * code that transitively imports Node built-ins (via @agentic-payments/shared's
 * env loader), which a browser bundler can't resolve. The in-browser wallet only
 * needs the SD-JWT crypto, the credential model, DCQL, and transaction_data —
 * none of which touch Node — so they are re-exported here for `@.../credentials/browser`.
 */
export * from "./crypto.ts";
export * from "./proof-credential.ts";
export * from "./dcql.ts";
export * from "./transaction-data.ts";
