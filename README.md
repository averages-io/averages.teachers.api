# Averages for Teachers API

The API behind teach.averages.io. It has no public address: the `averages.teachers` Worker forwards `teach.averages.io/api/*` here through a service binding.

## What's here (0.1.0)

| Route | Needs | What it does |
|---|---|---|
| `GET /api/health` | nothing | Up or not, and whether the secrets are set (yes or no only) |
| `POST /api/passkeys/register/options` | session | Starts adding a passkey |
| `POST /api/passkeys/register/verify` | session | Checks it and saves the public key |
| `POST /api/passkeys/signin/options` | nothing | Starts a passkey sign-in |
| `POST /api/passkeys/signin/verify` | nothing | Checks it and says which teacher it is |
| `GET /api/passkeys` | session | The teacher's passkeys (names and dates, no keys) |
| `DELETE /api/passkeys/:id` | session | Removes one |

"Session" means the `__Host-avt_session` cookie. "Log in with Schoology" sets it, and that comes next (milestone M1). Until then, only tests can make one.

A passkey sign-in only **identifies** the teacher. It can't reach Schoology on its own, because Schoology keys aren't stored by default. Level 2 will wrap the keys with the passkey's PRF output so a passkey can start a full session.

## Rules every request follows

- Anything that changes something needs our page's `Origin` and a JSON body (`src/guard.ts`).
- Answers are never cached or framed, and errors never include details.
- Passkeys need user verification (Touch ID, Windows Hello, a PIN). Attestation isn't requested.
- Cookies are `__Host-` cookies (Secure, Path=/, no Domain), so they can only belong to teach.averages.io.

## Storage

- One `TeacherStore` Durable Object per teacher, in the US jurisdiction.
- It keeps only passkeys: credential ID, public key, sign counter, name, dates. No secrets.
- At most 10 passkeys per teacher.

## Secrets

Set each once with `npx wrangler secret put <NAME>`:

- `SESSION_SECRET`: 32+ random bytes (`openssl rand -base64 32`)
- `SCHOOLOGY_CONSUMER_KEY` and `SCHOOLOGY_CONSUMER_SECRET`: the App Center app's (needed from M1)

## Run, test, deploy

- `npm ci`
- Local: copy `.dev.vars.example` to `.dev.vars` and fill in `SESSION_SECRET`. Then run `npm run dev` in `averages.teachers`, which starts both Workers.
- `npm test`: OAuth signing, sessions, health and guards, and passkeys end to end with real ES256, EdDSA and RS256 keys.
- `npm run build`: type check.
- `npm run deploy`: deploy this Worker before `averages.teachers`.

## License

GPL v3, like Averages.io.
