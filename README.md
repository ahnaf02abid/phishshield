# PhishShield

A rule-based phishing detection and cybersecurity awareness platform: URL scanner, email phishing analyzer, password strength + breach checker, awareness quiz, and an admin-configurable detection engine. Dark, red-accented UI with animated reports.

## Contents

- `phishshield.html` — the standalone frontend (single self-contained file; also served by the backend at `backend/public/index.html`)
- `backend/` — Express + MySQL API: authentication, saved scan history, admin panel (users, quiz, known domains, scoring weights), a k-anonymity breach-check API, and the advanced URL-analysis engine (hosting-infrastructure intel, brand-impersonation detection, phishing-kit fingerprinting, SSRF-safe page inspector, domain/DNS intel, threat-intel integrations)
- `build_breach_index.py` — builds the small in-page breach index used when the backend is not available
- `phishshield-*.html` — standalone animation/typography demo pages from earlier design exploration

## Quick start (frontend only)

Open `phishshield.html` directly in a browser. URL/email/password checks, the awareness quiz and the admin panel (demo mode, no login) all run client-side.

## Quick start (with backend: accounts, saved history, real admin auth)

```bash
cd backend
npm install
cp .env.example .env            # fill in DB credentials and SESSION_SECRET
npm run db:init
ADMIN_EMAIL=you@example.com ADMIN_PASSWORD='a-strong-password' npm run db:seed
npm start                        # http://localhost:3000
npm test                         # unit tests always run; DB tests run if a test database is reachable
```

See `backend/README.md` for the breach-database setup (k-anonymity SHA-1 lookup) and MySQL notes.

## Status / limitations

This is a rule-based, static-analysis tool — not a guaranteed phishing classifier. The advanced URL-analysis layers (page-content inspection, phishing-kit fingerprinting, domain/DNS intel, threat-intel feeds) are implemented as backend modules but are not yet wired into a public scan endpoint; see the module files under `backend/src/detect/` for their current state.
