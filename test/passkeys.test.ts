// Run: node --experimental-strip-types --import ./test/cf-loader.mjs test/passkeys.test.ts
// Passkeys end to end through the API, with real keys from test/softAuthenticator.ts and an
// in-memory store in place of the Durable Object.

import { createApp } from "../src/app.ts";
import { sealSession, SESSION_COOKIE, openValue } from "../src/session.ts";
import { MAX_PASSKEYS, type PasskeyRow, type PasskeyStore } from "../src/teacherStore.ts";
import { ALG_EDDSA, ALG_ES256, ALG_RS256, derToRaw, decodeCbor, WebAuthnError } from "../src/webauthn.ts";
import { CHALLENGE_COOKIE, IDENTITY_COOKIE, IDENTITY_PURPOSE, cleanName } from "../src/passkeys.ts";
import { SoftPasskey } from "./softAuthenticator.ts";

let passed = 0;
let failed = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (ok) passed++;
  else failed++;
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}${ok ? "" : `\n        expected: ${JSON.stringify(expected)}\n        actual:   ${JSON.stringify(actual)}`}`);
}

// ── in-memory stores, one per uid ──
const stores = new Map<string, Map<string, PasskeyRow>>();
let calls = 0;
const memStore = (uid: string): PasskeyStore => {
  calls++;
  const m = stores.get(uid) ?? new Map();
  stores.set(uid, m);
  return {
    async listPasskeys() { return [...m.values()]; },
    async getPasskey(id) { return m.get(id) ?? null; },
    async addPasskey(r) { if (m.size >= MAX_PASSKEYS || m.has(r.id)) return false; m.set(r.id, structuredClone(r)); return true; },
    async usedPasskey(id, n, at) { const r = m.get(id); if (r) { r.signCount = n; r.lastUsed = at; } },
    async removePasskey(id) { return m.delete(id); },
    async removeEverything() { m.clear(); },
  };
};

const app = createApp({ storeFor: (_env, uid) => memStore(uid) });
const ORIGIN = "https://teach.averages.io";
const RP = "teach.averages.io";
const ENV = { APP_ORIGIN: ORIGIN, RP_ID: RP, SESSION_SECRET: "test-secret-0123456789-0123456789-abcdef" };
const UID = "146180046";
const session = await sealSession({ uid: UID, token: "t", tokenSecret: "ts" }, ENV.SESSION_SECRET);

/** A browser: keeps cookies between calls. */
function browser(start: Record<string, string> = {}) {
  const jar = new Map(Object.entries(start));
  return async (method: string, path: string, body?: unknown, env: object = ENV) => {
    const headers: Record<string, string> = { Origin: ORIGIN, Cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; ") };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const r = await app.fetch(new Request(ORIGIN + "/api" + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }), env);
    for (const sc of r.headers.getSetCookie()) {
      const [kv, ...attrs] = sc.split("; ");
      const i = kv.indexOf("=");
      if (attrs.includes("Max-Age=0")) jar.delete(kv.slice(0, i));
      else jar.set(kv.slice(0, i), kv.slice(i + 1));
    }
    return { status: r.status, json: await r.json().catch(() => null), cookies: r.headers.getSetCookie(), jar };
  };
}

async function addPasskey(b: ReturnType<typeof browser>, pk: SoftPasskey, name = "School laptop") {
  const o = await b("POST", "/passkeys/register/options", { accountName: "Ms. Test" });
  const cred = await pk.create(o.json.publicKey);
  return b("POST", "/passkeys/register/verify", { credential: cred, name });
}

console.log("\nadding a passkey");
let b = browser({ [SESSION_COOKIE]: session });
let r = await b("POST", "/passkeys/register/options", {});
check("options 200", r.status, 200);
const pub = r.json.publicKey;
check("rp", pub.rp, { id: RP, name: "Averages for Teachers" });
check("user verification required", pub.authenticatorSelection.userVerification, "required");
check("discoverable", pub.authenticatorSelection.residentKey, "required");
check("attestation none", pub.attestation, "none");
check("algorithms", pub.pubKeyCredParams.map((p: any) => p.alg), [ALG_EDDSA, ALG_ES256, ALG_RS256]);
check("asks about PRF", pub.extensions.prf, {});
check("user handle is avt:uid", atob(pub.user.id.replace(/-/g, "+").replace(/_/g, "/")), "avt:" + UID);
check("challenge cookie is __Host-, Strict, short", /^__Host-avt_pkc=.+; Path=\/; HttpOnly; Secure; SameSite=Strict; Max-Age=300$/.test(r.cookies[0]), true);

const pk1 = new SoftPasskey({ rpId: RP, origin: ORIGIN });
const cred1 = await pk1.create(pub);
r = await b("POST", "/passkeys/register/verify", { credential: cred1, name: "School <b>laptop</b>" });
check("verify 200", r.status, 200);
check("summary, no key material", Object.keys(r.json.passkey).sort(), ["backedUp", "created", "id", "lastUsed", "name", "prf"]);
check("name cleaned", r.json.passkey.name, "School blaptop/b");
check("prf noted", r.json.passkey.prf, true);
check("unknown transports dropped", stores.get(UID)!.get(cred1.id)!.transports, ["internal"]);
check("challenge cookie cleared", r.jar.has(CHALLENGE_COOKIE), false);
r = await b("POST", "/passkeys/register/verify", { credential: cred1 });
check("same challenge can't be used twice", [r.status, r.json.error], [400, "expired"]);

r = await b("POST", "/passkeys/register/options", {});
check("existing passkeys are excluded next time", r.json.publicKey.excludeCredentials.map((x: any) => x.id), [cred1.id]);

console.log("\nadding: refused");
check("signed out: 401", (await browser()("POST", "/passkeys/register/options", {})).status, 401);
for (const [label, mutate] of [
  ["wrong origin", { origin: "https://evil.example" }],
  ["student app origin", { origin: "https://app.averages.io" }],
  ["wrong type", { type: "webauthn.get" }],
  ["wrong challenge", { challenge: "AAAA" }],
] as const) {
  const bb = browser({ [SESSION_COOKIE]: session });
  const o = await bb("POST", "/passkeys/register/options", {});
  const c = await new SoftPasskey({ rpId: RP, origin: ORIGIN }).create(o.json.publicKey, mutate as any);
  const v = await bb("POST", "/passkeys/register/verify", { credential: c });
  check(label, v.status, 400);
}
for (const [label, opts] of [
  ["wrong rp id", { rpId: "averages.io", origin: ORIGIN }],
  ["no user verification", { rpId: RP, origin: ORIGIN, uv: false }],
  ["no user presence", { rpId: RP, origin: ORIGIN, up: false }],
] as const) {
  const bb = browser({ [SESSION_COOKIE]: session });
  const o = await bb("POST", "/passkeys/register/options", {});
  const v = await bb("POST", "/passkeys/register/verify", { credential: await new SoftPasskey(opts).create(o.json.publicKey) });
  check(label, [v.status, v.json.reason], [400, label === "wrong rp id" ? "wrong_rp" : label === "no user verification" ? "no_user_verification" : "no_user_presence"]);
}
{
  // Another teacher's challenge cookie can't be used in this teacher's session.
  const other = await sealSession({ uid: "999", token: "t", tokenSecret: "ts" }, ENV.SESSION_SECRET);
  const bb = browser({ [SESSION_COOKIE]: other });
  const o = await bb("POST", "/passkeys/register/options", {});
  const c = await new SoftPasskey({ rpId: RP, origin: ORIGIN }).create(o.json.publicKey);
  bb; // swap the session, keep the challenge
  const swapped = browser({ [SESSION_COOKIE]: session, [CHALLENGE_COOKIE]: o.jar.get(CHALLENGE_COOKIE)! });
  check("challenge tied to the teacher", (await swapped("POST", "/passkeys/register/verify", { credential: c })).status, 400);
}
{
  const bb = browser({ [SESSION_COOKIE]: session });
  const o = await bb("POST", "/passkeys/register/options", {});
  const c = await new SoftPasskey({ rpId: RP, origin: ORIGIN }).create(o.json.publicKey);
  c.id = c.id.slice(0, -2) + "AA";
  check("id must match the authenticator data", (await bb("POST", "/passkeys/register/verify", { credential: c })).json.reason, "id_mismatch");
}
{
  const bb = browser({ [SESSION_COOKIE]: session });
  check("garbage body", (await bb("POST", "/passkeys/register/verify", { credential: "nope" })).status, 400);
}

console.log("\nsigning in with the passkey");
let anon = browser();
r = await anon("POST", "/passkeys/signin/options", {});
check("options without a session", r.status, 200);
check("uv required, no credential list (discoverable)", [r.json.publicKey.userVerification, r.json.publicKey.allowCredentials, r.json.publicKey.rpId], ["required", [], RP]);
let a = await pk1.get(r.json.publicKey);
r = await anon("POST", "/passkeys/signin/verify", { credential: a });
check("identified", [r.status, r.json], [200, { ok: true, uid: UID, prf: true }]);
const ident = await openValue(r.jar.get(IDENTITY_COOKIE)!, ENV.SESSION_SECRET, IDENTITY_PURPOSE);
check("identity cookie holds uid and passkey id", ident, { uid: UID, cid: cred1.id });
check("identity cookie is not a session", r.jar.has(SESSION_COOKIE), false);
check("counter and last used saved", [stores.get(UID)!.get(cred1.id)!.signCount, typeof stores.get(UID)!.get(cred1.id)!.lastUsed], [1, "number"]);
r = await anon("POST", "/passkeys/signin/verify", { credential: a });
check("replay of the same answer refused", r.status, 400);

for (const alg of [ALG_EDDSA, ALG_RS256]) {
  const pk = new SoftPasskey({ rpId: RP, origin: ORIGIN, alg });
  const added = await addPasskey(browser({ [SESSION_COOKIE]: session }), pk);
  const bb = browser();
  const o = await bb("POST", "/passkeys/signin/options", {});
  const v = await bb("POST", "/passkeys/signin/verify", { credential: await pk.get(o.json.publicKey) });
  check(`${alg === ALG_EDDSA ? "EdDSA" : "RS256"}: add and sign in`, [added.status, v.status], [200, 200]);
}

console.log("\nsigning in: refused");
const tryWith = async (mutate: (cred: any, pub: any) => Promise<any> | any) => {
  const bb = browser();
  const o = await bb("POST", "/passkeys/signin/options", {});
  const cred = await mutate(null, o.json.publicKey);
  return bb("POST", "/passkeys/signin/verify", { credential: cred });
};
let v = await tryWith((_c, p) => pk1.get(p, { origin: "https://evil.example" }));
check("wrong origin", [v.status, v.json], [400, { error: "passkey_refused" }]);
v = await tryWith((_c, p) => pk1.get(p, { rpId: "evil.example" }));
check("wrong rp", v.status, 400);
v = await tryWith((_c, p) => pk1.get(p, { type: "webauthn.create" }));
check("wrong type", v.status, 400);
v = await tryWith(async (_c, p) => { const x = await pk1.get(p); x.response.signature = x.response.signature.slice(0, -4) + "AAAA"; return x; });
check("bad signature", v.status, 400);
v = await tryWith(async (_c, p) => { const x = await pk1.get(p); x.response.userHandle = btoa("avt:999").replace(/=/g, ""); return x; });
check("someone else's uid in the handle", v.status, 400);
v = await tryWith(async (_c, p) => { const x = await pk1.get(p); x.response.userHandle = btoa("avt:../x").replace(/=/g, ""); return x; });
check("bad handle", v.status, 400);
v = await tryWith((_c, p) => pk1.get(p, { counter: 0 }));
check("counter went back", v.status, 400);
{
  const stranger = new SoftPasskey({ rpId: RP, origin: ORIGIN });
  await stranger.create({ user: { id: btoa("avt:" + UID).replace(/=/g, "") }, challenge: "AA" });
  v = await tryWith((_c, p) => stranger.get(p));
  check("a passkey we never registered", [v.status, v.json], [400, { error: "passkey_refused" }]);
}
{
  const bb = browser();
  const v2 = await bb("POST", "/passkeys/signin/verify", { credential: await pk1.get({ challenge: "AAAA" }) });
  check("no challenge cookie", [v2.status, v2.json.error], [400, "expired"]);
}
{
  // A registration challenge can't be used to sign in.
  const bb = browser({ [SESSION_COOKIE]: session });
  const o = await bb("POST", "/passkeys/register/options", {});
  const v2 = await bb("POST", "/passkeys/signin/verify", { credential: await pk1.get(o.json.publicKey) });
  check("registration challenge refused for sign-in", v2.status, 400);
}
{
  const before = calls;
  await tryWith(async (_c, p) => { const x = await pk1.get(p); x.id = "short"; return x; });
  check("bad id never reaches storage", calls, before);
}

console.log("\nlisting and removing");
b = browser({ [SESSION_COOKIE]: session });
r = await b("GET", "/passkeys");
check("list", [r.status, r.json.passkeys.length], [200, 3]);
check("no keys in the list", JSON.stringify(r.json).includes("jwk"), false);
check("list needs a session", (await browser()("GET", "/passkeys")).status, 401);
check("remove bad id", (await b("DELETE", "/passkeys/x")).status, 400);
check("remove unknown", (await b("DELETE", "/passkeys/" + "A".repeat(43))).status, 404);
check("remove", (await b("DELETE", "/passkeys/" + cred1.id)).status, 200);
v = await tryWith((_c, p) => pk1.get(p));
check("a removed passkey can't sign in", v.status, 400);
{
  const other = await sealSession({ uid: "555", token: "t", tokenSecret: "ts" }, ENV.SESSION_SECRET);
  const ob = browser({ [SESSION_COOKIE]: other });
  const id = [...stores.get(UID)!.keys()][0];
  check("another teacher can't remove mine", (await ob("DELETE", "/passkeys/" + id)).status, 404);
  check("mine is still there", stores.get(UID)!.has(id), true);
}

console.log("\nlimits and config");
{
  const uid = "777";
  const s = await sealSession({ uid, token: "t", tokenSecret: "ts" }, ENV.SESSION_SECRET);
  let last = 0;
  for (let i = 0; i <= MAX_PASSKEYS; i++) last = (await addPasskey(browser({ [SESSION_COOKIE]: s }), new SoftPasskey({ rpId: RP, origin: ORIGIN }))).status;
  check(`no more than ${MAX_PASSKEYS} passkeys`, [stores.get(uid)!.size, last], [MAX_PASSKEYS, 409]);
}
check("no RP_ID: 503", (await browser()("POST", "/passkeys/signin/options", {}, { ...ENV, RP_ID: "" })).status, 503);
{
  const blocked = { ...ENV, RATE_LIMIT_PASSKEY: { limit: async () => ({ success: false }) } };
  check("rate limited", (await browser()("POST", "/passkeys/signin/options", {}, blocked)).status, 429);
}
check("writes still need our origin", (await app.fetch(new Request(ORIGIN + "/api/passkeys/signin/options", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }), ENV)).status, 403);

console.log("\nparsers");
const err = (f: () => unknown) => { try { f(); return "none"; } catch (e) { return e instanceof WebAuthnError ? e.code : "other"; } };
check("cbor: truncated", err(() => decodeCbor(new Uint8Array([0x5f]))), "bad_cbor");
check("cbor: too deep", err(() => decodeCbor(new Uint8Array(40).fill(0x81))), "bad_cbor");
check("cbor: tags refused", err(() => decodeCbor(new Uint8Array([0xc0, 0]))), "bad_cbor");
check("der: junk", err(() => derToRaw(new Uint8Array([1, 2, 3]))), "bad_signature");
check("name: empty becomes Passkey", cleanName("  "), "Passkey");
check("name: capped at 40", cleanName("x".repeat(99)).length, 40);

console.log(`\n${passed} passed, ${failed} failed`);
if (failed) process.exit(1);
