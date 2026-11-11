// Passkey routes: add one while signed in, sign in with one, list them, remove one.
//
// What "sign in with a passkey" gives today: it identifies the teacher (their Schoology uid)
// and nothing more. It can't open Schoology by itself, because the Schoology keys aren't stored
// at Level 1. Level 2 (later) adds keys wrapped with the passkey's PRF output, so a passkey
// sign-in can unwrap them and start a real session.
//
// Challenges are sealed in a short-lived host-only cookie, tied to the teacher (when adding)
// and to what they're for, then cleared once used.

import { Hono, type Context } from "hono";
import type { Env } from "./env.ts";
import { allowedOrigins } from "./guard.ts";
import { openSession, openValue, readCookie, sealValue, SESSION_COOKIE, type TeacherSession } from "./session.ts";
import { summary, type PasskeyStore } from "./teacherStore.ts";
import {
  b64url,
  fromB64url,
  newChallenge,
  SUPPORTED_ALGS,
  uidFromUserHandle,
  userHandleFor,
  verifyAssertion,
  verifyRegistration,
  WebAuthnError,
} from "./webauthn.ts";

export const CHALLENGE_COOKIE = "__Host-avt_pkc";
export const IDENTITY_COOKIE = "__Host-avt_pkid";
const CHALLENGE_PURPOSE = "passkey-challenge-v1";
export const IDENTITY_PURPOSE = "passkey-identity-v1";
const CHALLENGE_TTL = 5 * 60;
const IDENTITY_TTL = 10 * 60;
const TIMEOUT_MS = 3 * 60 * 1000;

export type StoreFor = (env: Env, uid: string) => PasskeyStore;

/**
 * The real store: this teacher's Durable Object, in the US jurisdiction.
 * Local dev (workerd) has no jurisdictions, so .dev.vars sets DO_JURISDICTION=none.
 * Unset means "us": production can never quietly fall back to storing elsewhere.
 */
export const durableStore: StoreFor = (env, uid) => {
  const ns = env.DO_JURISDICTION === "none" ? env.TEACHER! : env.TEACHER!.jurisdiction("us");
  return ns.get(ns.idFromName(uid)) as unknown as PasskeyStore;
};

type Vars = { session: TeacherSession };
type C = Context<{ Bindings: Env; Variables: Vars }>;

const cookie = (name: string, value: string, maxAge: number) =>
  [`${name}=${value}`, "Path=/", "HttpOnly", "Secure", "SameSite=Strict", `Max-Age=${maxAge}`].join("; ");

/** A name the teacher gives a passkey ("School laptop"): plain text, short. */
export function cleanName(v: unknown): string {
  const s = typeof v === "string" ? v.replace(/[\u0000-\u001f\u007f<>]/g, "").replace(/\s+/g, " ").trim().slice(0, 40) : "";
  return s || "Passkey";
}

const CRED_ID = /^[A-Za-z0-9_-]{16,1400}$/;

async function body(c: C): Promise<Record<string, any>> {
  try {
    const b = await c.req.json();
    return b && typeof b === "object" ? b : {};
  } catch {
    return {};
  }
}

function config(c: C) {
  const rpId = String(c.env.RP_ID ?? "").trim();
  const secret = String(c.env.SESSION_SECRET ?? "");
  return rpId && secret ? { rpId, secret, origins: allowedOrigins(c.env) } : null;
}

async function limited(c: C, key: string): Promise<boolean> {
  const rl = c.env.RATE_LIMIT_PASSKEY;
  if (!rl) return false;
  const { success } = await rl.limit({ key });
  return !success;
}

const clientIp = (c: C) => c.req.header("CF-Connecting-IP") ?? "unknown";

export function passkeyRoutes(storeFor: StoreFor = durableStore) {
  const r = new Hono<{ Bindings: Env; Variables: Vars }>();

  // Every route needs the Worker configured; the ones that change a teacher's passkeys need a session.
  r.use("*", async (c, next) => {
    if (!config(c)) return c.json({ error: "not_configured" }, 503);
    return next();
  });
  const signedIn = async (c: C, next: () => Promise<void>) => {
    const token = readCookie(c.req.header("Cookie"), SESSION_COOKIE);
    const s = token ? await openSession(token, c.env.SESSION_SECRET!) : null;
    if (!s) return c.json({ error: "signed_out" }, 401);
    c.set("session", s);
    await next();
  };

  // ── add a passkey (signed in) ──

  r.post("/register/options", signedIn, async (c) => {
    const { rpId, secret } = config(c)!;
    const s = c.get("session");
    if (await limited(c, `reg:${s.uid}`)) return c.json({ error: "slow_down" }, 429);
    const b = await body(c);
    const existing = await storeFor(c.env, s.uid).listPasskeys();
    const challenge = newChallenge();
    const sealed = await sealValue({ c: b64url(challenge), uid: s.uid, k: "reg" }, secret, CHALLENGE_PURPOSE, CHALLENGE_TTL);
    c.header("Set-Cookie", cookie(CHALLENGE_COOKIE, sealed, CHALLENGE_TTL));
    const label = typeof b.accountName === "string" ? cleanName(b.accountName) : "Averages for Teachers";
    return c.json({
      publicKey: {
        rp: { id: rpId, name: "Averages for Teachers" },
        user: { id: userHandleFor(s.uid), name: label, displayName: label },
        challenge: b64url(challenge),
        pubKeyCredParams: SUPPORTED_ALGS.map((alg) => ({ type: "public-key", alg })),
        timeout: TIMEOUT_MS,
        attestation: "none",
        authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
        excludeCredentials: existing.map((p) => ({ type: "public-key", id: p.id, transports: p.transports })),
        // Asks whether the passkey can do PRF, which Level 2 needs to wrap keys.
        extensions: { credProps: true, prf: {} },
      },
    });
  });

  r.post("/register/verify", signedIn, async (c) => {
    const { rpId, secret, origins } = config(c)!;
    const s = c.get("session");
    const ch = (await openValue(readCookie(c.req.header("Cookie"), CHALLENGE_COOKIE) ?? "", secret, CHALLENGE_PURPOSE)) as any;
    c.header("Set-Cookie", cookie(CHALLENGE_COOKIE, "", 0));
    if (!ch || ch.k !== "reg" || ch.uid !== s.uid) return c.json({ error: "expired" }, 400);
    const b = await body(c);
    try {
      const cred = await verifyRegistration(b.credential, { challenge: fromB64url(ch.c), origins, rpId });
      const now = Date.now();
      const row = { ...cred, name: cleanName(b.name), created: now, lastUsed: null };
      const added = await storeFor(c.env, s.uid).addPasskey(row);
      if (!added) return c.json({ error: "too_many_or_taken" }, 409);
      return c.json({ ok: true, passkey: summary(row) });
    } catch (e) {
      if (e instanceof WebAuthnError) return c.json({ error: "passkey_refused", reason: e.code }, 400);
      throw e;
    }
  });

  // ── sign in with a passkey (identifies the teacher only, see the top of this file) ──

  r.post("/signin/options", async (c) => {
    const { rpId, secret } = config(c)!;
    if (await limited(c, `in:${clientIp(c)}`)) return c.json({ error: "slow_down" }, 429);
    const challenge = newChallenge();
    const sealed = await sealValue({ c: b64url(challenge), k: "auth" }, secret, CHALLENGE_PURPOSE, CHALLENGE_TTL);
    c.header("Set-Cookie", cookie(CHALLENGE_COOKIE, sealed, CHALLENGE_TTL));
    return c.json({ publicKey: { challenge: b64url(challenge), rpId, timeout: TIMEOUT_MS, userVerification: "required", allowCredentials: [] } });
  });

  r.post("/signin/verify", async (c) => {
    const { rpId, secret, origins } = config(c)!;
    if (await limited(c, `in:${clientIp(c)}`)) return c.json({ error: "slow_down" }, 429);
    const ch = (await openValue(readCookie(c.req.header("Cookie"), CHALLENGE_COOKIE) ?? "", secret, CHALLENGE_PURPOSE)) as any;
    const clear = cookie(CHALLENGE_COOKIE, "", 0);
    if (!ch || ch.k !== "auth") return c.json({ error: "expired" }, 400, { "Set-Cookie": clear });
    const b = await body(c);
    const cred = b.credential;
    const uid = uidFromUserHandle(cred?.response?.userHandle);
    // One answer for every failure below, so nobody can learn which uids or passkeys exist.
    const refused = () => c.json({ error: "passkey_refused" }, 400, { "Set-Cookie": clear });
    if (!uid || typeof cred?.id !== "string" || !CRED_ID.test(cred.id)) return refused();
    const store = storeFor(c.env, uid);
    const row = await store.getPasskey(cred.id);
    if (!row) return refused();
    try {
      const { signCount } = await verifyAssertion(cred, row, { challenge: fromB64url(ch.c), origins, rpId });
      await store.usedPasskey(row.id, signCount, Date.now());
    } catch (e) {
      if (e instanceof WebAuthnError) return refused();
      throw e;
    }
    const identity = await sealValue({ uid, cid: row.id }, secret, IDENTITY_PURPOSE, IDENTITY_TTL);
    c.header("Set-Cookie", clear, { append: true });
    c.header("Set-Cookie", cookie(IDENTITY_COOKIE, identity, IDENTITY_TTL), { append: true });
    return c.json({ ok: true, uid, prf: row.prf });
  });

  // ── manage (signed in) ──

  r.get("/", signedIn, async (c) => {
    const rows = await storeFor(c.env, c.get("session").uid).listPasskeys();
    return c.json({ passkeys: rows.map(summary) });
  });

  r.delete("/:id", signedIn, async (c) => {
    const id = c.req.param("id") ?? "";
    if (!CRED_ID.test(id)) return c.json({ error: "bad_id" }, 400);
    const ok = await storeFor(c.env, c.get("session").uid).removePasskey(id);
    return ok ? c.json({ ok: true }) : c.json({ error: "not_found" }, 404);
  });

  return r;
}
