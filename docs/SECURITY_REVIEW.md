# Repository Security & Risk Review (Case Study LMS)

Date: 2026-02-24
Scope: `/workspace/leave-management-case-study`

## Sensitive-data review summary

I did **not** find direct evidence of real company secrets (real domains, internal hostnames, private keys, or production credentials) in tracked files. Most identities and domains appear intentionally sanitized (`example.com`).

## Key risks/problems found

### 1) Insecure default secrets in Compose (High)
- `POSTGRES_PASSWORD` and `JWT_SECRET` fall back to hardcoded defaults when `.env` is missing.
- Risk: accidental deployment with predictable credentials and weak JWT signing secret.
- Evidence: `docker-compose.yml` defaults for `POSTGRES_PASSWORD` and `JWT_SECRET`.

### 2) Broad CORS policy (Medium)
- API enables `cors()` without origin restrictions.
- Risk: any origin can make authenticated browser calls if token/session is present.
- Evidence: `app.use(cors())` in API bootstrap.

### 3) SMTP secret handling is weak (High)
- SMTP password is stored plaintext in DB and returned via API to frontend.
- Risk: credential exposure to privileged UI clients, logs, DB snapshots, backups.
- Evidence: schema stores SMTP `password`; API returns full `smtp_config`; frontend writes `config.password` back into password input.

### 4) JWT token persisted in `localStorage` (Medium)
- Token is stored in browser `localStorage`.
- Risk: token theft if XSS occurs.
- Evidence: login flow stores `token` and `user` in local storage.

### 5) No repo guardrails for local secret artifacts (Medium)
- No `.gitignore` existed initially, increasing risk of accidental commits of `.env`, certs, backups, and uploads.
- Action taken in this review: added `.gitignore` to block common sensitive/runtime files.

## Additional observations

- Seed data includes demo users and known default password policy (`staff_code + lms`). This is acceptable for a case study but should never be reused for non-demo environments.
- `api/node_modules` appeared as untracked local content; now ignored to reduce accidental noise/commits.

## Recommendations (prioritized)

1. **Fail fast on missing required secrets** (remove insecure fallbacks; exit startup when `JWT_SECRET` or DB password missing).
2. **Restrict CORS** to explicit origins via env config.
3. **Protect SMTP credentials**:
   - avoid returning stored SMTP password to clients,
   - encrypt at rest or use external secret manager,
   - provide one-way “set/update” behavior for password fields.
4. **Move auth token to HttpOnly secure cookies** and add CSP/XSS hardening.
5. **Keep sanitization pipeline explicit** before publishing:
   - run secret scanning (`gitleaks`/`trufflehog`),
   - verify no real certificate/backup files are present.
