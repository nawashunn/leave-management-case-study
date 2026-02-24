# Case Study LMS (Public-Safe Edition)

This repository is a sanitized case-study version of a Leave Management System.
It is prepared for portfolio/interview presentation and excludes confidential company data.

## What Was Sanitized
- Removed real secrets and credentials (`.env`, TLS password values, JWT secrets).
- Removed private certificates and backup dumps.
- Removed internal company docs and original screenshots.
- Replaced company-specific domains/emails with `example.com` placeholders.
- Kept only demonstration-safe sample accounts and data.

## Quick Start

### 1. Configure environment
```bash
cp .env.example .env
```
Then set strong values for:
- `POSTGRES_PASSWORD`
- `JWT_SECRET`

### 2. Start services
```bash
docker compose up -d
```

### 3. Open app
- HTTP: `http://localhost:8080`
- API health: `http://localhost:3000/api/health`

Note: HTTPS (`8443`) requires a local `.pfx` certificate in `certs/` and `TLS_CERT_PASSWORD` in `.env`.

## Demo Accounts
Default password policy in this case study is `staff_code + lms`.

- Superadmin: `it@example.com` / `IT001lms`
- Admin: `leave@example.com` / `ADMINlms`
- Approver: `john@example.com` / `MG001lms`
- Employee: `mary@example.com` / `OF001lms`
- Retail employee: `RT001` / `RT001lms`
- Retail supervisor: `supervisor@example.com` / `DJ001lms`

## Portfolio Tips
Use this project to explain:
- Role-based workflow design (employee/approver/admin/superadmin)
- SQL schema and audit strategy
- Balance calculation and leave lifecycle logic
- Operational safety features (backup/restore, retention controls)

## Before Publishing to GitHub
- Confirm `.env` is not committed.
- Confirm `certs/` contains no real certificates.
- Confirm `backups/` contains no real dumps.
- Add sanitized screenshots into `docs/screenshots/` if needed.
