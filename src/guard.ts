// Rules every request goes through, before any route.

import type { MiddlewareHandler } from "hono";
import type { Env } from "./env.ts";

/** Headers on every API answer. Nothing from the API is cached or framed. */
export const apiHeaders: MiddlewareHandler<{ Bindings: Env }> = async (c, next) => {
  await next();
  const h = c.res.headers;
  h.set("Cache-Control", h.get("Cache-Control") ?? "no-store");
  h.set("X-Content-Type-Options", "nosniff");
  h.set("Referrer-Policy", "no-referrer");
  h.set("X-Frame-Options", "DENY");
  h.set("Cross-Origin-Resource-Policy", "same-origin");
  h.set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
};

/** The origins pages may call from: APP_ORIGIN, comma-separated. */
export function allowedOrigins(env: Env): string[] {
  return String(env.APP_ORIGIN ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

const SAFE = new Set(["GET", "HEAD", "OPTIONS"]);

/**
 * Anything that changes something must come from our own pages, as JSON.
 * Stops other sites from posting forms at the API with the teacher's cookie
 * (including login CSRF), and keeps every write route to one shape.
 */
export const sameOriginWrites: MiddlewareHandler<{ Bindings: Env }> = async (c, next) => {
  if (SAFE.has(c.req.method)) return next();
  const origin = c.req.header("Origin");
  if (!origin || !allowedOrigins(c.env).includes(origin)) return c.json({ error: "bad_origin" }, 403);
  const type = (c.req.header("Content-Type") ?? "").split(";")[0].trim().toLowerCase();
  if (c.req.method !== "DELETE" && type !== "application/json") return c.json({ error: "json_only" }, 415);
  return next();
};
