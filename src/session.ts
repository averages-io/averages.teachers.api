// Teacher sessions: sealed (AES-GCM), host-only cookies. Nothing is stored on the server.
//
// Adapted from averages.api/src/session.ts. What's different for teachers:
// - The cookie holds the teacher's Schoology access token and token secret from
//   "Log in with Schoology". The app's consumer key and secret never go in it;
//   they stay Worker secrets.
// - The cookie is `__Host-` prefixed, so browsers refuse it unless it's Secure,
//   Path=/ and has no Domain. It can only ever belong to teach.averages.io.
// - Every sealed value has a purpose, so a token sealed for one job can't be
//   replayed as another (a session can't pass as a sign-in state, and so on).

/** How long a sign-in lasts. Open question for Martin: a working day or a week. */
export const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7;
export const SESSION_COOKIE = "__Host-avt_session";
const SESSION_PURPOSE = "teacher-session-v1";
/** The secret must be at least this long (32 random bytes in base64 is 44). */
export const MIN_SECRET_LENGTH = 32;

export interface TeacherSession {
  /** Schoology user id, numeric. */
  uid: string;
  /** Three-legged OAuth access token and token secret. */
  token: string;
  tokenSecret: string;
  /** The school's Schoology address used to sign in, like "app.schoology.com". */
  sd?: string;
  /** Unix seconds. */
  exp: number;
}

function b64urlEncode(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) throw new Error("bad base64url");
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

/** A separate AES-256-GCM key per purpose, derived from the Worker secret with HKDF. */
async function purposeKey(secret: string, purpose: string): Promise<CryptoKey> {
  if (typeof secret !== "string" || secret.length < MIN_SECRET_LENGTH) throw new Error("SESSION_SECRET is missing or too short");
  const ikm = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new TextEncoder().encode("averages-teachers"), info: new TextEncoder().encode(purpose) },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

const now = () => Math.floor(Date.now() / 1000);

/** Seals any JSON value for one purpose, for ttlSeconds. */
export async function sealValue(value: unknown, secret: string, purpose: string, ttlSeconds: number): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await purposeKey(secret, purpose);
  const payload = JSON.stringify({ v: value, x: now() + ttlSeconds });
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(payload));
  return `${b64urlEncode(iv)}.${b64urlEncode(new Uint8Array(ct))}`;
}

/** The value sealed for this purpose, or null (wrong purpose or secret, tampered, expired, malformed). */
export async function openValue(token: string, secret: string, purpose: string): Promise<unknown> {
  try {
    if (typeof token !== "string" || token.length > 4096) return null;
    const [ivPart, dataPart, extra] = token.split(".");
    if (!ivPart || !dataPart || extra !== undefined) return null;
    const iv = b64urlDecode(ivPart);
    if (iv.length !== 12) return null;
    const key = await purposeKey(secret, purpose);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, b64urlDecode(dataPart));
    const data = JSON.parse(new TextDecoder().decode(plain));
    if (!data || typeof data.x !== "number" || data.x < now()) return null;
    return data.v ?? null;
  } catch {
    return null;
  }
}

const isId = (v: unknown): v is string => typeof v === "string" && /^[0-9]{1,20}$/.test(v);
const isSecretText = (v: unknown): v is string => typeof v === "string" && v.length > 0 && v.length <= 512;

export async function sealSession(data: Omit<TeacherSession, "exp">, secret: string): Promise<string> {
  const exp = now() + SESSION_TTL_SECONDS;
  return sealValue({ ...data, exp }, secret, SESSION_PURPOSE, SESSION_TTL_SECONDS);
}

/** The session, or null for anything we didn't seal, anything tampered with, or anything expired. */
export async function openSession(token: string, secret: string): Promise<TeacherSession | null> {
  const v = (await openValue(token, secret, SESSION_PURPOSE)) as Record<string, unknown> | null;
  if (!v || typeof v !== "object") return null;
  if (!isId(v.uid) || !isSecretText(v.token) || !isSecretText(v.tokenSecret)) return null;
  if (typeof v.exp !== "number" || v.exp < now()) return null;
  if (v.sd !== undefined && (typeof v.sd !== "string" || v.sd.length > 253)) return null;
  const s: TeacherSession = { uid: v.uid, token: v.token, tokenSecret: v.tokenSecret, exp: v.exp };
  if (typeof v.sd === "string") s.sd = v.sd;
  return s;
}

export function sessionCookie(token: string, maxAge: number = SESSION_TTL_SECONDS): string {
  return [`${SESSION_COOKIE}=${token}`, "Path=/", "HttpOnly", "Secure", "SameSite=Lax", `Max-Age=${Math.max(0, Math.floor(maxAge))}`].join("; ");
}

export function clearSessionCookie(): string {
  return [`${SESSION_COOKIE}=`, "Path=/", "HttpOnly", "Secure", "SameSite=Lax", "Max-Age=0"].join("; ");
}

export function readCookie(header: string | null | undefined, name: string): string | null {
  if (!header) return null;
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    if (part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}
