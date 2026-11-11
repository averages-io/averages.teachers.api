// A software passkey for tests: makes registration and sign-in answers the way a browser and
// authenticator would, with real keys (ES256, EdDSA or RS256), so verification is tested for real.

import { ALG_EDDSA, ALG_ES256, ALG_RS256, b64url, sha256 } from "../src/webauthn.ts";

// ── a tiny CBOR writer ──
type V = number | string | Uint8Array | Map<V, V>;
function head(major: number, n: number): number[] {
  if (n < 24) return [(major << 5) | n];
  if (n < 256) return [(major << 5) | 24, n];
  if (n < 65536) return [(major << 5) | 25, n >> 8, n & 255];
  return [(major << 5) | 26, (n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255];
}
export function cbor(v: V): Uint8Array {
  const out: number[] = [];
  const w = (x: V) => {
    if (typeof x === "number") out.push(...(x >= 0 ? head(0, x) : head(1, -1 - x)));
    else if (typeof x === "string") {
      const b = new TextEncoder().encode(x);
      out.push(...head(3, b.length), ...b);
    } else if (x instanceof Uint8Array) out.push(...head(2, x.length), ...x);
    else {
      out.push(...head(5, x.size));
      for (const [k, val] of x) {
        w(k);
        w(val);
      }
    }
  };
  w(v);
  return new Uint8Array(out);
}

const cat = (...p: Uint8Array[]) => {
  const o = new Uint8Array(p.reduce((n, x) => n + x.length, 0));
  let i = 0;
  for (const x of p) {
    o.set(x, i);
    i += x.length;
  }
  return o;
};
const u32 = (n: number) => new Uint8Array([(n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255]);
const fromB64 = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));

/** raw r||s → DER, as real authenticators send ES256 signatures. */
export function rawToDer(raw: Uint8Array): Uint8Array {
  const int = (b: Uint8Array) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    let v = b.slice(i);
    if (v[0] & 0x80) v = cat(new Uint8Array([0]), v);
    return cat(new Uint8Array([2, v.length]), v);
  };
  const body = cat(int(raw.slice(0, 32)), int(raw.slice(32)));
  return cat(new Uint8Array([0x30, body.length]), body);
}

export interface Options {
  rpId: string;
  origin: string;
  alg?: number;
  /** Flags to send: user present and verified by default. */
  up?: boolean;
  uv?: boolean;
  counter?: number;
}

export class SoftPasskey {
  id = crypto.getRandomValues(new Uint8Array(32));
  counter: number;
  alg: number;
  keys!: CryptoKeyPair;
  userHandle = "";
  o: Options;
  constructor(o: Options) {
    this.o = o;
    this.alg = o.alg ?? ALG_ES256;
    this.counter = o.counter ?? 0;
  }

  private async cose(): Promise<Uint8Array> {
    const jwk = await crypto.subtle.exportKey("jwk", this.keys.publicKey);
    if (this.alg === ALG_ES256) return cbor(new Map<V, V>([[1, 2], [3, ALG_ES256], [-1, 1], [-2, fromB64(jwk.x!)], [-3, fromB64(jwk.y!)]]));
    if (this.alg === ALG_EDDSA) return cbor(new Map<V, V>([[1, 1], [3, ALG_EDDSA], [-1, 6], [-2, fromB64(jwk.x!)]]));
    return cbor(new Map<V, V>([[1, 3], [3, ALG_RS256], [-1, fromB64(jwk.n!)], [-2, fromB64(jwk.e!)]]));
  }

  private flags(attested: boolean) {
    return (this.o.up === false ? 0 : 1) | (this.o.uv === false ? 0 : 4) | (attested ? 0x40 : 0);
  }

  async create(publicKey: any, extra: { origin?: string; type?: string; challenge?: string } = {}) {
    this.keys = (await crypto.subtle.generateKey(
      this.alg === ALG_ES256
        ? { name: "ECDSA", namedCurve: "P-256" }
        : this.alg === ALG_EDDSA
          ? { name: "Ed25519" }
          : { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    this.userHandle = publicKey.user.id;
    const clientData = new TextEncoder().encode(
      JSON.stringify({ type: extra.type ?? "webauthn.create", challenge: extra.challenge ?? publicKey.challenge, origin: extra.origin ?? this.o.origin, crossOrigin: false }),
    );
    const rpHash = await sha256(new TextEncoder().encode(this.o.rpId));
    const authData = cat(rpHash, new Uint8Array([this.flags(true)]), u32(this.counter), new Uint8Array(16), new Uint8Array([0, this.id.length]), this.id, await this.cose());
    const att = cbor(new Map<V, V>([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]));
    return {
      id: b64url(this.id),
      rawId: b64url(this.id),
      type: "public-key",
      response: { clientDataJSON: b64url(clientData), attestationObject: b64url(att), transports: ["internal", "made-up"] },
      clientExtensionResults: { prf: { enabled: true } },
    };
  }

  async get(publicKey: any, extra: { origin?: string; type?: string; rpId?: string; counter?: number } = {}) {
    this.counter = extra.counter ?? this.counter + 1;
    const clientData = new TextEncoder().encode(JSON.stringify({ type: extra.type ?? "webauthn.get", challenge: publicKey.challenge, origin: extra.origin ?? this.o.origin }));
    const rpHash = await sha256(new TextEncoder().encode(extra.rpId ?? this.o.rpId));
    const authData = cat(rpHash, new Uint8Array([this.flags(false)]), u32(this.counter));
    const data = cat(authData, await sha256(clientData));
    let sig = new Uint8Array(
      await crypto.subtle.sign(
        this.alg === ALG_ES256 ? { name: "ECDSA", hash: "SHA-256" } : this.alg === ALG_EDDSA ? { name: "Ed25519" } : { name: "RSASSA-PKCS1-v1_5" },
        this.keys.privateKey,
        data,
      ),
    );
    if (this.alg === ALG_ES256) sig = rawToDer(sig);
    return {
      id: b64url(this.id),
      rawId: b64url(this.id),
      type: "public-key",
      response: { clientDataJSON: b64url(clientData), authenticatorData: b64url(authData), signature: b64url(sig), userHandle: this.userHandle },
      clientExtensionResults: {},
    };
  }
}
