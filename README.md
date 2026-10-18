# Hisab Kitab — deployable full-stack starter

Premium responsive shop-management app for Pakistani retailers. Includes a floating animated AI-orb button, chat drawer, browser speech input/output, secure account passwords, server-side sessions, SQLite persistence, inventory, sales, expenses, udhaar, reports, and an admin users view.

## Run locally (Windows)
1. Install Python 3.11+.
2. Open a terminal in this folder.
3. Run `py -m venv .venv` then activate it: `.venv\\Scripts\\activate`.
4. Run `pip install -r requirements.txt`.
5. Copy `.env.example` to `.env` and set a unique `ADMIN_PASSWORD`. The app does not automatically read `.env`, so set environment variables in your terminal or use your hosting dashboard.
6. Start: `uvicorn main:app --reload`.
7. Open http://127.0.0.1:8000.

PowerShell environment example:
```powershell
$env:ADMIN_EMAIL="admin@yourdomain.com"
$env:ADMIN_PASSWORD="a-long-unique-password"
$env:COOKIE_SECURE="0"
uvicorn main:app --reload
```

## AI setup
The AI-orb button opens a working chat panel. Without `HF_TOKEN`, the assistant still answers common shop questions from the real database using a transparent rules fallback. For generative AI, create a Hugging Face token with inference access and add `HF_TOKEN` in the hosting environment. `HF_MODEL` defaults to `Qwen/Qwen2.5-7B-Instruct`; availability/limits depend on Hugging Face's current inference provider access. Do not put tokens in frontend code or commit them to Git.

Browser microphone recognition uses the browser's Web Speech API (best tested in current Chrome, served on localhost or HTTPS). Browser support and Urdu recognition quality vary. Speech output uses the browser's built-in speech synthesis. Voice input is sent as recognized text to the server, not as a raw audio recording.

## Deploy
- Docker: `docker build -t hisabkitab-store .` then run with environment variables. For persistent data mount a volume at `/var/data` and set `DATABASE_PATH=/var/data/hisabkitab.db`.
- Render: the included `render.yaml` describes a Docker web service with a persistent disk. Review plan pricing in Render before deploying; persistent disks may require a paid plan. Add `ADMIN_EMAIL`, `ADMIN_PASSWORD`, and optionally `HF_TOKEN` as secret environment variables. Never deploy with the example/default admin password.
- On any host, use HTTPS and persistent storage for the SQLite database. For multiple app instances or higher traffic, migrate to managed PostgreSQL before public commercial use.

## Current limitations / production checklist
- This is a working MVP, not audited production financial software. Back up the database; test all totals before using real shop records.
- AI is advisory/reporting only; sales and stock changes happen through explicit forms, not ambiguous AI instructions.
- Admin users are provisioned from `ADMIN_EMAIL`/`ADMIN_PASSWORD`; public signup can only create shopkeeper accounts.
- The starter includes an admin user list but not user suspension, password reset email, payment integration, or udhaar repayment workflow yet.
- Configure a unique strong admin password before first startup. The initial admin is created once; changing env vars later does not change an existing admin password in the database.
