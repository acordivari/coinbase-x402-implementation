/**
 * OIDC layer. The human authenticates with an Identity Provider and the
 * Authorization Service consumes the resulting ID token. We support two modes
 * behind one `IdentityVerifier` seam:
 *
 *   - local : a spec-shaped OIDC issuer running in-process (offline tests/demo)
 *   - auth0 : a real Auth0 tenant, verified against its remote JWKS
 *
 * Either way, verification yields a `Principal` (the human's verified identity)
 * that gets bound into the Intent mandate.
 */
import {
  createLocalJWKSet,
  createRemoteJWKSet,
  jwtVerify,
  SignJWT,
  type JWTPayload,
  type JWTVerifyGetKey,
} from "jose";
import { Principal, type Principal as PrincipalT } from "@agentic-payments/shared";
import { toJwks, type SigningKeyPair } from "./keys.ts";

export interface PrincipalClaims {
  sub: string;
  email?: string;
  emailVerified?: boolean;
}

/** A local, spec-shaped OIDC issuer for offline mode (signs ID tokens). */
export class LocalOidcIssuer {
  constructor(
    readonly issuer: string,
    readonly audience: string,
    private readonly key: SigningKeyPair,
  ) {}

  async mintIdToken(claims: PrincipalClaims, ttlSeconds = 3600): Promise<string> {
    return new SignJWT({
      email: claims.email,
      email_verified: claims.emailVerified,
    })
      .setProtectedHeader({ alg: this.key.alg, kid: this.key.kid })
      .setIssuer(this.issuer)
      .setAudience(this.audience)
      .setSubject(claims.sub)
      .setIssuedAt()
      .setExpirationTime(`${ttlSeconds}s`)
      .sign(this.key.privateKey);
  }

  /** The JWKS a verifier uses to validate this issuer's tokens. */
  jwks() {
    return toJwks(this.key);
  }
}

export interface IdentityVerifierConfig {
  issuer: string;
  audience: string;
  getKey: JWTVerifyGetKey;
}

/** Verifies an OIDC ID token and returns the verified human Principal. */
export class IdentityVerifier {
  constructor(private readonly config: IdentityVerifierConfig) {}

  async verify(idToken: string): Promise<PrincipalT> {
    const { payload } = await jwtVerify(idToken, this.config.getKey, {
      issuer: this.config.issuer,
      audience: this.config.audience,
    });
    return principalFromClaims(payload);
  }
}

function principalFromClaims(payload: JWTPayload): PrincipalT {
  return Principal.parse({
    sub: payload.sub,
    idp: payload.iss,
    email: (payload as { email?: string }).email,
    emailVerified: (payload as { email_verified?: boolean }).email_verified,
  });
}

/** Build a verifier for the in-process local issuer. */
export function localVerifier(issuer: LocalOidcIssuer): IdentityVerifier {
  return new IdentityVerifier({
    issuer: issuer.issuer,
    audience: issuer.audience,
    getKey: createLocalJWKSet(issuer.jwks()),
  });
}

/** Build a verifier for a real Auth0 tenant (remote JWKS). */
export function auth0Verifier(opts: {
  domain: string;
  audience: string;
}): IdentityVerifier {
  const issuer = `https://${opts.domain}/`;
  return new IdentityVerifier({
    issuer,
    audience: opts.audience,
    getKey: createRemoteJWKSet(new URL(`${issuer}.well-known/jwks.json`)),
  });
}
