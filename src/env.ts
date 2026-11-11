// What the Worker is given. Secrets are set with `npx wrangler secret put <NAME>`, never in wrangler.jsonc.

export interface Env {
  /** Where the pages live, comma-separated. "https://teach.averages.io" in production. */
  APP_ORIGIN: string;
  /** The passkey "relying party": the host passkeys belong to. "teach.averages.io" in production, "localhost" in dev. */
  RP_ID?: string;
  /** Seals session and passkey cookies. 32+ random bytes. Secret. */
  SESSION_SECRET?: string;
  /** The App Center app's consumer key and secret (same app as the student side). Secrets. Needed from M1. */
  SCHOOLOGY_CONSUMER_KEY?: string;
  SCHOOLOGY_CONSUMER_SECRET?: string;
  /** "none" only in local dev, where Durable Object jurisdictions don't exist. Never set in production. */
  DO_JURISDICTION?: string;
  /** One TeacherStore Durable Object per teacher (src/teacherStore.ts). */
  TEACHER?: DurableObjectNamespace;
  /** Workers Rate Limiting binding for the passkey routes. Optional: without it there's no limit. */
  RATE_LIMIT_PASSKEY?: { limit(o: { key: string }): Promise<{ success: boolean }> };
}
