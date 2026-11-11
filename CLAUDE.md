# Averages for Teachers API

The rules, plan and milestones live in the sibling repo: read `../averages.teachers/CLAUDE.md` first, then the docs it lists in `../averages.teachers/handoff/`. Everything there applies here.

The short version for this repo:
- Fixed action routes only. Never forward a browser-chosen Schoology path or method.
- Keys never reach the browser, logs or error messages. Secrets only through `npx wrangler secret put`.
- Every write goes through `sameOriginWrites` (our Origin, JSON). Every section a route touches is checked against the teacher's own sections first.
- Store as little as possible, US jurisdiction only.
- `src/index.ts` may only export the handler and Durable Object classes. Build routes in `src/app.ts` and its modules.
- Imports keep their `.ts` extensions. Run `npm test` and `npm run build` before delivering.
- No TypeScript parameter properties or enums: Node's type stripping can't run them.
- Never commit or push. Martin uploads.
