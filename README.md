# SilentSOS — Cloud Deployment Bundle (free tier)

This repository contains **only the files needed to run SilentSOS in the cloud**.
Application development (dashboard `src/`, tests, firmware, docs) happens in the
local Silent_SOS project — this repo is intentionally minimal and deploy-ready
only: FastAPI backend + built React dashboard in one container.

> **Note:** the editable source code (dashboard `src/`, tests, firmware, docs)
> is NOT here. This repo is intentionally minimal — deploy-ready only.

## What's inside

```
├── Dockerfile           # single image: FastAPI + dashboard (one URL)
├── render.yaml          # Render Blueprint — click-to-deploy
├── requirements.txt     # Python dependencies (pinned)
├── .dockerignore        # keeps the build context tiny
├── app/                 # FastAPI source (backend)
├── dist/                # built React dashboard (served at / by the API)
└── README.md            # this file
```

## Free platform choice

| Piece | Service | Free tier |
|---|---|---|
| API + Dashboard | **Render.com** web service (Docker) | 750 hrs/mo, sleeps after 15 min idle |
| PostgreSQL | **Neon.tech** | 0.5 GB, always free, never expires |

## Deploy step-by-step (≈15 minutes)

### 1. Create the free database (Neon)
1. Sign up at https://neon.tech (GitHub login works).
2. Create a project named `silentsos`.
3. Copy the connection string:
   ```
   postgresql://user:password@ep-xxx.region.aws.neon.tech/neondb?sslmode=require
   ```

### 2. Deploy on Render
1. Sign up at https://render.com (GitHub login works).
2. Dashboard → **New +** → **Blueprint** → select this repo (`SilentSOS`).
3. Render reads `render.yaml` and asks for `DATABASE_URL` — paste the **Neon**
   connection string from step 1.
4. Click **Apply**. First build takes ~5 minutes (Docker + pip install).

### 3. Get the admin password
Render → service `silentsos` → **Logs** → look for:
```
BOOTSTRAP ADMIN CREATED: admin@silentsos.local / <generated password>
```
Log in at `https://<your-service>.onrender.com/`, create a real admin, then
deactivate the bootstrap account.

### 4. Fix CORS for the final URL
After the first deploy you know the real URL (e.g.
`https://silentsos-xxxx.onrender.com`). The dashboard is served from the SAME
origin so it works out of the box — but update **Environment → CORS_ORIGINS**
to that URL anyway so external tools/devices can call the API.

## Updating the app
Code is developed in the main SilentSOS project. When the API or dashboard
changes, publish the updated bundle with one command from the local project:
```powershell
powershell -File "deploy\minimal\publish.ps1"          # refresh + force-push
powershell -File "deploy\minimal\publish.ps1" -DryRun  # stage only, no push
```
It rebuilds the dashboard, refreshes `app/` + `dist/`, and pushes a fresh
single commit to this repo — Render auto-redeploys.

## Important free-tier notes
- **Render free disk is ephemeral.** SQLite would be wiped on every redeploy —
  that's why `DATABASE_URL` must point to Neon Postgres.
- **Wake-up delay:** first request after idle takes ~50 s; a `/health` probe
  (e.g. free UptimeRobot) can keep it warm.
- **Neon autosuspends** idle branches (~5 s cold start) — fine for this load.
- **MQTT is disabled** (`MQTT_ENABLED=false`). Devices use the SMS/webhook path,
  which is the designed behaviour for the SIM provider.
- **SMS provider is `sim`** (events logged, not really sent). Add
  Fast2SMS/Twilio credentials in Render → Environment for real SMS.
