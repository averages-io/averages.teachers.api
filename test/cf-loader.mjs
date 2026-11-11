// Lets Node load files that import "cloudflare:workers" (the Durable Object base class).
// Run: node --experimental-strip-types --import ./test/cf-loader.mjs test/<file>.test.ts
import { register } from "node:module";

const hooks = `
export async function resolve(specifier, context, next) {
  if (specifier === "cloudflare:workers") {
    return {
      shortCircuit: true,
      url: "data:text/javascript," + encodeURIComponent("export class DurableObject { constructor(ctx, env) { this.ctx = ctx; this.env = env; } }"),
    };
  }
  return next(specifier, context);
}
`;
register("data:text/javascript," + encodeURIComponent(hooks));
