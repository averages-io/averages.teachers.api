// WebAuthn (passkeys), verified with Web Crypto only. No library, so there's nothing to keep
// in step with Workers. Covers what Averages for Teachers asks browsers for:
// - attestation "none" (we don't care which device made the key, only that it's the same one later)
// - user verification required (Touch ID, Windows Hello, a PIN): a teacher token is too strong for presence alone
// - ES256, EdDSA and RS256 keys
// Spec: https://www.w3.org/TR/webauthn-3/

export const ALG_ES256 = -7;
export const ALG_EDDSA = -8;
export const ALG_RS256 = -257;
export const SUPPORTED_ALGS = [ALG_EDDSA, ALG_ES256, ALG_RS256] as const;

export class WebAuthnError extends Error {
  code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
    this.name = "WebAuthnError";
  }
}
const fail = (code: string): never => {
  throw new WebAuthnError(code);
};

// ── bytes ──

export function b64url(bytes: Uint8Array | ArrayBuffer): string {
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (const b of u) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64url(value: unknown, max = 16384): Uint8Array {
  if (typeof value !== "string" || value.length > max || !/^[A-Za-z0-9_-]*$/.test(value)) fail("bad_encoding");
  const v = value as string;
  const padded = v.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

export const sha256 = async (data: Uint8Array): Promise<Uint8Array> => new Uint8Array(await crypto.subtle.digest("SHA-256", data));

function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

// ── a small CBOR reader, enough for attestation objects and COSE keys ──

type Cbor = number | bigint | string | Uint8Array | Cbor[] | Map<Cbor, Cbor> | boolean | null | undefined;

export function decodeCbor(bytes: Uint8Array): { value: Cbor; end: number } {
  let pos = 0;
  let depth = 0;
  const need = (n: number) => {
    if (pos + n > bytes.length) fail("bad_cbor");
  };
  const readLen = (info: number): number => {
    if (info < 24) return info;
    if (info === 24) {
      need(1);
      return bytes[pos++];
    }
    if (info === 25) {
      need(2);
      const v = (bytes[pos] << 8) | bytes[pos + 1];
      pos += 2;
      return v;
    }
    if (info === 26) {
      need(4);
      const v = ((bytes[pos] << 24) >>> 0) + (bytes[pos + 1] << 16) + (bytes[pos + 2] << 8) + bytes[pos + 3];
      pos += 4;
      return v;
    }
    return fail("bad_cbor"); // 64-bit lengths and indefinite lengths never appear here
  };
  const item = (): Cbor => {
    if (++depth > 16) fail("bad_cbor");
    need(1);
    const first = bytes[pos++];
    const major = first >> 5;
    const info = first & 31;
    let out: Cbor;
    switch (major) {
      case 0:
        out = readLen(info);
        break;
      case 1:
        out = -1 - readLen(info);
        break;
      case 2: {
        const n = readLen(info);
        need(n);
        out = bytes.slice(pos, pos + n);
        pos += n;
        break;
      }
      case 3: {
        const n = readLen(info);
        need(n);
        out = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes.subarray(pos, pos + n));
        pos += n;
        break;
      }
      case 4: {
        const n = readLen(info);
        if (n > 64) fail("bad_cbor");
        const arr: Cbor[] = [];
        for (let i = 0; i < n; i++) arr.push(item());
        out = arr;
        break;
      }
      case 5: {
        const n = readLen(info);
        if (n > 64) fail("bad_cbor");
        const m = new Map<Cbor, Cbor>();
        for (let i = 0; i < n; i++) {
          const k = item();
          m.set(k, item());
        }
        out = m;
        break;
      }
      case 7:
        out = info === 20 ? false : info === 21 ? true : info === 22 ? null : fail("bad_cbor");
        break;
      default:
        out = fail("bad_cbor"); // tags (6) aren't used by WebAuthn
    }
    depth--;
    return out;
  };
  const value = item();
  return { value, end: pos };
}

// ── COSE public keys → JWK ──

export interface StoredKey {
  alg: number;
  jwk: JsonWebKey;
}

export function coseToJwk(cose: Cbor): StoredKey {
  if (!(cose instanceof Map)) return fail("bad_key");
  const m = cose as Map<Cbor, Cbor>;
  const kty = m.get(1);
  const alg = m.get(3);
  const bytes = (k: number) => {
    const v = m.get(k);
    return v instanceof Uint8Array ? v : fail("bad_key");
  };
  if (alg === ALG_ES256 && kty === 2 && m.get(-1) === 1) {
    const x = bytes(-2), y = bytes(-3);
    if (x.length !== 32 || y.length !== 32) fail("bad_key");
    return { alg, jwk: { kty: "EC", crv: "P-256", x: b64url(x), y: b64url(y) } };
  }
  if (alg === ALG_EDDSA && kty === 1 && m.get(-1) === 6) {
    const x = bytes(-2);
    if (x.length !== 32) fail("bad_key");
    return { alg, jwk: { kty: "OKP", crv: "Ed25519", x: b64url(x) } };
  }
  if (alg === ALG_RS256 && kty === 3) {
    const n = bytes(-1), e = bytes(-2);
    if (n.length < 256) fail("bad_key"); // 2048-bit or more
    return { alg, jwk: { kty: "RSA", n: b64url(n), e: b64url(e) } };
  }
  return fail("unsupported_key");
}

async function importKey(k: StoredKey): Promise<CryptoKey> {
  if (k.alg === ALG_ES256) return crypto.subtle.importKey("jwk", k.jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  if (k.alg === ALG_EDDSA) return crypto.subtle.importKey("jwk", k.jwk, { name: "Ed25519" }, false, ["verify"]);
  if (k.alg === ALG_RS256) return crypto.subtle.importKey("jwk", k.jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  return fail("unsupported_key");
}

/** Authenticators sign ES256 in DER; Web Crypto wants the raw 64-byte r || s. */
export function derToRaw(der: Uint8Array): Uint8Array {
  let p = 0;
  const byte = () => (p < der.length ? der[p++] : fail("bad_signature"));
  if (byte() !== 0x30) fail("bad_signature");
  let len = byte();
  if (len & 0x80) {
    if (len !== 0x81) fail("bad_signature");
    len = byte();
  }
  if (p + len !== der.length) fail("bad_signature");
  const int = () => {
    if (byte() !== 0x02) fail("bad_signature");
    const n = byte();
    if (n < 1 || n > 33 || p + n > der.length) fail("bad_signature");
    let v = der.slice(p, p + n);
    p += n;
    while (v.length > 32 && v[0] === 0) v = v.slice(1);
    if (v.length > 32) fail("bad_signature");
    const out = new Uint8Array(32);
    out.set(v, 32 - v.length);
    return out;
  };
  const r = int(), s = int();
  if (p !== der.length) fail("bad_signature");
  return concat(r, s);
}

async function verifySignature(k: StoredKey, signature: Uint8Array, data: Uint8Array): Promise<boolean> {
  const key = await importKey(k);
  if (k.alg === ALG_ES256) return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, derToRaw(signature), data);
  if (k.alg === ALG_EDDSA) return crypto.subtle.verify({ name: "Ed25519" }, key, signature, data);
  return crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key, signature, data);
}

// ── authenticator data ──

export interface AuthData {
  rpIdHash: Uint8Array;
  userPresent: boolean;
  userVerified: boolean;
  backupEligible: boolean;
  backedUp: boolean;
  signCount: number;
  credentialId?: Uint8Array;
  key?: StoredKey;
}

export function parseAuthData(a: Uint8Array): AuthData {
  if (a.length < 37) fail("bad_auth_data");
  const flags = a[32];
  const out: AuthData = {
    rpIdHash: a.slice(0, 32),
    userPresent: !!(flags & 0x01),
    userVerified: !!(flags & 0x04),
    backupEligible: !!(flags & 0x08),
    backedUp: !!(flags & 0x10),
    signCount: ((a[33] << 24) >>> 0) + (a[34] << 16) + (a[35] << 8) + a[36],
  };
  if (flags & 0x40) {
    if (a.length < 55) fail("bad_auth_data");
    const idLen = (a[53] << 8) | a[54];
    if (idLen < 16 || idLen > 1023 || 55 + idLen > a.length) fail("bad_auth_data");
    out.credentialId = a.slice(55, 55 + idLen);
    const { value, end } = decodeCbor(a.subarray(55 + idLen));
    out.key = coseToJwk(value);
    // Extension data (flag 0x80) may follow the key; anything else is junk.
    if (!(flags & 0x80) && 55 + idLen + end !== a.length) fail("bad_auth_data");
  }
  return out;
}

// ── client data ──

interface Expected {
  /** The challenge we sent, as bytes. */
  challenge: Uint8Array;
  /** Origins pages may run on ("https://teach.averages.io"). */
  origins: string[];
  rpId: string;
}

async function checkClientData(clientDataJSON: Uint8Array, type: string, exp: Expected): Promise<void> {
  let cd: any;
  try {
    cd = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(clientDataJSON));
  } catch {
    fail("bad_client_data");
  }
  if (!cd || cd.type !== type) fail("wrong_type");
  if (typeof cd.challenge !== "string" || !equal(fromB64url(cd.challenge, 512), exp.challenge)) fail("wrong_challenge");
  if (typeof cd.origin !== "string" || !exp.origins.includes(cd.origin)) fail("wrong_origin");
  if (cd.crossOrigin === true) fail("cross_origin");
}

async function checkRp(auth: AuthData, rpId: string): Promise<void> {
  if (!equal(auth.rpIdHash, await sha256(new TextEncoder().encode(rpId)))) fail("wrong_rp");
  if (!auth.userPresent) fail("no_user_presence");
  if (!auth.userVerified) fail("no_user_verification");
}

// ── registration ──

export interface RegistrationInput {
  id: unknown;
  rawId?: unknown;
  type?: unknown;
  response?: { clientDataJSON?: unknown; attestationObject?: unknown; transports?: unknown };
  clientExtensionResults?: { prf?: { enabled?: unknown } };
}

export interface NewCredential {
  id: string;
  key: StoredKey;
  signCount: number;
  backedUp: boolean;
  transports: string[];
  /** The browser said the passkey supports the PRF extension (needed for Level 2). */
  prf: boolean;
}

const TRANSPORTS = new Set(["usb", "nfc", "ble", "internal", "hybrid", "smart-card"]);

export async function verifyRegistration(input: RegistrationInput, exp: Expected): Promise<NewCredential> {
  if (!input || typeof input !== "object" || input.type !== "public-key" || !input.response) fail("bad_request");
  const clientDataJSON = fromB64url(input.response!.clientDataJSON, 4096);
  const attObj = fromB64url(input.response!.attestationObject, 16384);
  await checkClientData(clientDataJSON, "webauthn.create", exp);

  const { value } = decodeCbor(attObj);
  if (!(value instanceof Map)) return fail("bad_attestation");
  const authBytes = value.get("authData");
  if (!(authBytes instanceof Uint8Array)) return fail("bad_attestation");
  // We ask for attestation "none", so the statement isn't checked: trust comes from the
  // signed-in Schoology session that started this, not from the device maker.
  const auth = parseAuthData(authBytes);
  await checkRp(auth, exp.rpId);
  if (!auth.credentialId || !auth.key) fail("bad_attestation");

  const id = b64url(auth.credentialId!);
  if (input.id !== id) fail("id_mismatch");
  const transports = Array.isArray(input.response!.transports)
    ? (input.response!.transports as unknown[]).filter((t): t is string => typeof t === "string" && TRANSPORTS.has(t)).slice(0, 6)
    : [];
  return { id, key: auth.key!, signCount: auth.signCount, backedUp: auth.backedUp, transports, prf: input.clientExtensionResults?.prf?.enabled === true };
}

// ── sign-in ──

export interface AssertionInput {
  id: unknown;
  type?: unknown;
  response?: { clientDataJSON?: unknown; authenticatorData?: unknown; signature?: unknown; userHandle?: unknown };
}

export interface StoredCredential {
  id: string;
  key: StoredKey;
  signCount: number;
}

/** Checks a sign-in against the stored passkey and returns its new sign count. */
export async function verifyAssertion(input: AssertionInput, cred: StoredCredential, exp: Expected): Promise<{ signCount: number }> {
  if (!input || typeof input !== "object" || input.type !== "public-key" || !input.response) fail("bad_request");
  if (input.id !== cred.id) fail("id_mismatch");
  const clientDataJSON = fromB64url(input.response!.clientDataJSON, 4096);
  const authBytes = fromB64url(input.response!.authenticatorData, 4096);
  const signature = fromB64url(input.response!.signature, 1024);
  await checkClientData(clientDataJSON, "webauthn.get", exp);
  const auth = parseAuthData(authBytes);
  await checkRp(auth, exp.rpId);
  const data = concat(authBytes, await sha256(clientDataJSON));
  if (!(await verifySignature(cred.key, signature, data))) fail("bad_signature");
  // A counter that goes backwards means the key may have been copied. Synced passkeys always send 0.
  if ((auth.signCount !== 0 || cred.signCount !== 0) && auth.signCount <= cred.signCount) fail("counter_went_back");
  return { signCount: auth.signCount };
}

/** The Schoology uid we put in the passkey's user handle ("avt:<uid>"), or null. */
export function uidFromUserHandle(value: unknown): string | null {
  try {
    const s = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(fromB64url(value, 128));
    const m = /^avt:([0-9]{1,20})$/.exec(s);
    return m ? m[1] : null;
  } catch {
    return null;
  }
}

export const userHandleFor = (uid: string): string => b64url(new TextEncoder().encode(`avt:${uid}`));

export const newChallenge = (): Uint8Array => crypto.getRandomValues(new Uint8Array(32));
