// Run: node --experimental-strip-types --import ./test/cf-loader.mjs test/health.test.ts
// The app as a whole: health, unknown routes, headers, and the same-origin rule for writes.

import { app } from "../src/app.ts";

let passed = 0;
let failed = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (ok) passed++;
  else failed++;
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}${ok ? "" : `\n        expected: ${JSON.stringify(expected)}\n        actual:   ${JSON.stringify(actual)}`}`);
}

const ORIGIN = "https://teach.averages.io";
const FULL = {
  APP_ORIGIN: ORIGIN,
  RP_ID: "teach.averages.io",
  SESSION_SECRET: "test-secret-0123456789-0123456789-abcdef",
  SCHOOLOGY_CONSUMER_KEY: "k",
  SCHOOLOGY_CONSUMER_SECRET: "s",
};
const call = (path: string, init: RequestInit = {}, env: object = FULL) => app.fetch(new Request(ORIGIN + path, init), env);

console.log("\nhealth");
let r = await call("/api/health");
check("200", r.status, 200);
const body = await r.json();
check("body", body, { ok: true, service: "averages-teachers-api", version: "0.1.0", configured: true });
check("not cached", r.headers.get("Cache-Control"), "no-store");
check("nosniff", r.headers.get("X-Content-Type-Options"), "nosniff");
check("no framing", r.headers.get("X-Frame-Options"), "DENY");
check("CORP same-origin", r.headers.get("Cross-Origin-Resource-Policy"), "same-origin");
check("no CORS opened", r.headers.get("Access-Control-Allow-Origin"), null);

r = await call("/api/health", {}, { APP_ORIGIN: ORIGIN });
check("missing secrets: configured false", (await r.json()).configured, false);
r = await call("/api/health", {}, { ...FULL, SESSION_SECRET: "short" });
check("short session secret: configured false", (await r.json()).configured, false);
r = await call("/api/health", {}, FULL);
check("secret values never in the answer", (await r.text()).includes(FULL.SESSION_SECRET), false);

console.log("\nunknown routes");
r = await call("/api/nope");
check("404", r.status, 404);
check("404 body", await r.json(), { error: "not_found" });
check("404 still has headers", r.headers.get("X-Content-Type-Options"), "nosniff");
r = await call("/health");
check("outside /api is not served", r.status, 404);

console.log("\nwrites need our origin and JSON");
const json = { "Content-Type": "application/json" };
r = await call("/api/health", { method: "POST", headers: json, body: "{}" });
check("no Origin: 403", r.status, 403);
check("no Origin body", await r.json(), { error: "bad_origin" });
r = await call("/api/health", { method: "POST", headers: { ...json, Origin: "https://app.averages.io" }, body: "{}" });
check("student app origin: 403", r.status, 403);
r = await call("/api/health", { method: "POST", headers: { ...json, Origin: "https://evil.example" }, body: "{}" });
check("other site: 403", r.status, 403);
r = await call("/api/health", { method: "POST", headers: { Origin: ORIGIN, "Content-Type": "application/x-www-form-urlencoded" }, body: "a=1" });
check("form post from our origin: 415", r.status, 415);
r = await call("/api/health", { method: "POST", headers: { ...json, Origin: ORIGIN }, body: "{}" });
check("JSON from our origin passes the guard (then 404, no such route)", r.status, 404);
r = await call("/api/health", { method: "DELETE", headers: { Origin: ORIGIN } });
check("DELETE from our origin needs no body", r.status, 404);
r = await call("/api/health", { method: "POST", headers: { ...json, Origin: "http://localhost:8788" }, body: "{}" }, { ...FULL, APP_ORIGIN: `${ORIGIN}, http://localhost:8788` });
check("a listed dev origin passes", r.status, 404);

console.log(`\n${passed} passed, ${failed} failed`);
if (failed) process.exit(1);
