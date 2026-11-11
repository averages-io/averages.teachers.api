// The API's routes. src/index.ts is the Worker entry (it may only export handlers and
// Durable Object classes, so the app is built here).

import { Hono } from "hono";
import type { Env } from "./env.ts";
import { apiHeaders, sameOriginWrites } from "./guard.ts";
import { durableStore, passkeyRoutes, type StoreFor } from "./passkeys.ts";
import { MIN_SECRET_LENGTH } from "./session.ts";

export const VERSION = "0.1.0";

export interface Deps {
  /** Where a teacher's passkeys live. Tests pass an in-memory one. */
  storeFor?: StoreFor;
}

export function createApp(deps: Deps = {}) {
  const app = new Hono<{ Bindings: Env }>().basePath("/api");

  app.use("*", apiHeaders);
  app.use("*", sameOriginWrites);

  /** Is the Worker up, and are the secrets it needs set? Says yes or no only, never which. */
  app.get("/health", (c) => {
    const configured =
      String(c.env.SESSION_SECRET ?? "").length >= MIN_SECRET_LENGTH &&
      !!c.env.SCHOOLOGY_CONSUMER_KEY &&
      !!c.env.SCHOOLOGY_CONSUMER_SECRET &&
      !!c.env.RP_ID;
    return c.json({ ok: true, service: "averages-teachers-api", version: VERSION, configured });
  });

  app.route("/passkeys", passkeyRoutes(deps.storeFor ?? durableStore));

  app.notFound((c) => c.json({ error: "not_found" }, 404));

  app.onError((err, c) => {
    // The name only: messages can carry request details.
    console.error("unhandled", err instanceof Error ? err.name : typeof err);
    return c.json({ error: "server_error" }, 500);
  });

  return app;
}

export const app = createApp();
