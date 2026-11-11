// Run: node --experimental-strip-types test/session.test.ts
// The cookie carries a teacher's Schoology token, which can change many students' grades.
// Reading, forging, replaying or repurposing it would be a real leak, so each gets a test.

import {
  clearSessionCookie,
  openSession,
  openValue,
  readCookie,
  sealSession,
  sealValue,
  SESSION_COOKIE,
  SESSION_TTL_SECONDS,
  sessionCookie,
} from "../src/session.ts";

let passed = 0;
let failed = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (ok) passed++;
  else failed++;
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}${ok ? "" : `\n        expected: ${JSON.stringify(expected)}\n        actual:   ${JSON.stringify(actual)}`}`);
}
const yes = (name: string, v: boolean) => check(name, v, true);

const SECRET = "test-secret-0123456789-0123456789-abcdef";
const DATA = { uid: "146180046", token: "tok-abc-123", tokenSecret: "toksecret-xyz-789", sd: "app.schoology.com" };

console.log("\nround trip");
const t = await sealSession(DATA, SECRET);
const s = await openSession(t, SECRET);
check("uid", s?.uid, DATA.uid);
check("token", s?.token, DATA.token);
check("token secret", s?.tokenSecret, DATA.tokenSecret);
check("school address", s?.sd, DATA.sd);
const left = (s?.exp ?? 0) - Math.floor(Date.now() / 1000);
yes("expires in about the session length", left > SESSION_TTL_SECONDS - 5 && left <= SESSION_TTL_SECONDS);

console.log("\nconfidentiality");
yes("token not readable", !t.includes(DATA.token));
yes("token secret not readable", !t.includes(DATA.tokenSecret));
yes("uid not readable", !t.includes(DATA.uid));
yes("two seals differ (random IV)", t !== (await sealSession(DATA, SECRET)));

console.log("\nintegrity");
check("wrong secret", await openSession(t, SECRET + "x"), null);
const [iv, body] = t.split(".");
const flip = body.slice(0, 10) + (body[10] === "A" ? "B" : "A") + body.slice(11);
check("one changed character", await openSession(`${iv}.${flip}`, SECRET), null);
check("cut short", await openSession(t.slice(0, -4), SECRET), null);
check("extra part", await openSession(t + ".x", SECRET), null);
check("not base64url", await openSession("@@@.###", SECRET), null);
check("empty", await openSession("", SECRET), null);
check("huge", await openSession("A".repeat(5000) + ".A", SECRET), null);

console.log("\npurpose");
const other = await sealValue({ ...DATA, exp: Math.floor(Date.now() / 1000) + 60 }, SECRET, "signin-state", 60);
check("a value sealed for another purpose is not a session", await openSession(other, SECRET), null);
check("a session is not another purpose's value", await openValue(t, SECRET, "signin-state"), null);

console.log("\nshape");
const bad = async (v: unknown) => openSession(await sealValue(v, SECRET, "teacher-session-v1", 60), SECRET);
const exp = Math.floor(Date.now() / 1000) + 60;
check("uid must be numeric", await bad({ ...DATA, uid: "abc", exp }), null);
check("token required", await bad({ ...DATA, token: "", exp }), null);
check("token secret required", await bad({ ...DATA, tokenSecret: undefined, exp }), null);
check("exp required", await bad({ ...DATA }), null);
check("past exp", await bad({ ...DATA, exp: 1 }), null);
check("extra fields are dropped", Object.keys((await bad({ ...DATA, exp, admin: true })) ?? {}).sort(), ["exp", "sd", "token", "tokenSecret", "uid"]);

console.log("\nexpiry");
const short = await sealValue("x", SECRET, "p", -1);
check("expired value", await openValue(short, SECRET, "p"), null);

console.log("\nsecret");
let threw = false;
try {
  await sealSession(DATA, "short");
} catch {
  threw = true;
}
yes("a short secret is refused when sealing", threw);
check("a short secret opens nothing", await openSession(t, "short"), null);

console.log("\ncookies");
const c = sessionCookie("abc");
yes("__Host- prefix", c.startsWith("__Host-avt_session=abc"));
yes("HttpOnly", c.includes("HttpOnly"));
yes("Secure", c.includes("Secure"));
yes("SameSite=Lax", c.includes("SameSite=Lax"));
yes("Path=/", c.includes("Path=/"));
yes("no Domain (host-only)", !/domain=/i.test(c));
yes("clearing: Max-Age=0, same name", clearSessionCookie().startsWith(`${SESSION_COOKIE}=;`) && clearSessionCookie().includes("Max-Age=0"));
check("read cookie", readCookie(`a=1; ${SESSION_COOKIE}=xyz.abc; b=2`, SESSION_COOKIE), "xyz.abc");
check("read missing cookie", readCookie("a=1", SESSION_COOKIE), null);
check("read with no header", readCookie(null, SESSION_COOKIE), null);
check("a look-alike name doesn't match", readCookie(`x${SESSION_COOKIE}=evil`, SESSION_COOKIE), null);

console.log(`\n${passed} passed, ${failed} failed`);
if (failed) process.exit(1);
