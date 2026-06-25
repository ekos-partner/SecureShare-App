# Deployment Guide

This guide covers deploying SecureShare to various environments.

## Prerequisites

- Node.js 22+ (if running natively)
- Docker (recommended for self-hosted)
- A reverse proxy (Nginx, Caddy, Traefik) for HTTPS when not using a managed platform

## 🗄️ Which database should I use?

| Scenario | Recommended backend | Why |
| :--- | :--- | :--- |
| **Self-hosted** (Docker, VPS, homelab, dev) | **SQLite** (default) | Simple, no external services, one file on disk (`data/secrets.db`). |
| **Other PaaS** (Render, Railway, VPS + disk) | **SQLite** + persistent volume | Same as self-hosted — mount `./data` or set `DB_PATH`. |
| **Google Cloud Run** (serverless, scale-to-zero) | **Cloud Firestore** | Local SQLite is **ephemeral** on Cloud Run — links die after idle sleep. Firestore persists without a shared disk. |

> **Rule of thumb:** If you are **not** on GCP Cloud Run, stay on **SQLite**. You do not need Firebase or any `FIREBASE_*` variables.

The app auto-selects the provider unless you override it with `DATABASE_PROVIDER=sqlite` or `DATABASE_PROVIDER=firestore`.

---

## 🐳 Self-Hosted: Docker (Recommended)

The easiest way to run your **own** instance is Docker with **SQLite**. No Firebase setup required.

The repository includes `docker-compose.yml`:

```bash
docker compose up -d
```

This mounts `./data` → `/app/data` and stores secrets in `data/secrets.db`.

> **✅ Self-hosted SQLite — links do not “randomly” break**  
> As long as `./data` is mounted (as in `docker-compose.yml`), secrets survive container restarts and reboots.  
> **❌ Links will break if you:** run `docker run` **without** `-v …/data`, use `docker compose down -v` (removes volumes), or delete `data/secrets.db` manually.

### Manual Docker Build

```bash
docker build -t secureshare .
docker run -d -p 3000:3000 \
  -v "$(pwd)/data:/app/data" \
  -e NODE_ENV=production \
  -e APP_URL=https://your-domain.example \
  --name secureshare secureshare
```

### Native (without Docker)

```bash
npm install
npm run build
NODE_ENV=production APP_URL=https://your-domain.example npm run start:prod
```

SQLite file: `./data/secrets.db` (override with `DB_PATH`).

### Self-hosted environment variables

| Variable | Typical value | Notes |
| :--- | :--- | :--- |
| `NODE_ENV` | `production` | Required for security headers |
| `APP_URL` | `https://your-domain.example` | CORS in production |
| `DB_PATH` | `./data/secrets.db` | SQLite file location |
| `DATABASE_PROVIDER` | *(omit)* or `sqlite` | Explicit SQLite (optional) |
| `TRUST_PROXY` | `1` | Behind Nginx/Caddy/Traefik |

**Do not set** `FIREBASE_CONFIG` or `FIREBASE_*` on a self-hosted SQLite deployment unless you intentionally want Firestore.

---

## ☁️ Google Cloud Platform (Cloud Run + Firestore)

Firestore exists **for GCP serverless** — especially Cloud Run, where the container filesystem is not durable.

### Why not SQLite on Cloud Run?

When Firestore is not configured, the app falls back to SQLite in the container. After scale-to-zero or a new revision, that file is gone and users see **“Link Invalid”**. The web UI shows a warning banner in this situation.

### Recommended: Cloud Run + Firestore

1. **Firestore**
   - Enable Firestore in your Firebase / GCP project.
   - Deploy security rules from this repo:
     ```bash
     firebase deploy --only firestore:rules
     ```

2. **Firebase credentials (never commit to Git)**

   Choose **one** method — all are read at runtime only:

   **Option A — `FIREBASE_CONFIG` (best for Cloud Run Secret Manager)**  
   Single JSON string, e.g. in Secret Manager:
   ```json
   {"apiKey":"…","authDomain":"….firebaseapp.com","projectId":"…","firestoreDatabaseId":"(default)"}
   ```

   **Option B — individual variables**  
   `FIREBASE_PROJECT_ID`, `FIREBASE_API_KEY`, `FIREBASE_AUTH_DOMAIN`, optional `FIREBASE_FIRESTORE_DATABASE_ID`.

   **Option C — local file (dev / private image only)**  
   `firebase-applet-config.json` in the project root (gitignored). Prefer env vars on Cloud Run.

3. **Build & push image** (Artifact Registry example)
   ```bash
   gcloud builds submit --tag REGION-docker.pkg.dev/PROJECT_ID/secureshare/app:latest
   ```

4. **Deploy Cloud Run**
   - Port: **3000**
   - Environment:
     - `NODE_ENV=production`
     - `DATABASE_PROVIDER=firestore`
     - `APP_URL=https://YOUR_CLOUD_RUN_URL`
     - `FIREBASE_CONFIG` from Secret Manager *(or Option B variables)*
   - **No** persistent disk needed for the database.

   Example:
   ```bash
   gcloud run deploy secureshare \
     --image REGION-docker.pkg.dev/PROJECT_ID/secureshare/app:latest \
     --port 3000 \
     --set-env-vars NODE_ENV=production,DATABASE_PROVIDER=firestore,APP_URL=https://YOUR_URL \
     --set-secrets FIREBASE_CONFIG=firebase-config:latest
   ```

5. **API key hygiene** — restrict the Firebase Web API key in Google Cloud Console (HTTP referrers, API allowlists).

### Alternative on GCP: SQLite + Cloud Storage volume

Only if you accept SQLite limitations on serverless (low concurrency, volume mount complexity):

- Mount a GCS bucket via Cloud Storage FUSE (e.g. `/data`).
- `DATABASE_PROVIDER=sqlite`
- `DB_PATH=/data/secrets.db`

For most Cloud Run deployments, **Firestore is the better choice**.

---

## Other Cloud Providers (Render / Railway / Heroku)

Treat these like **self-hosted SQLite**:

1. Build: `npm run build`
2. Start: `npm run start:prod`
3. Attach a **persistent volume** at `/app/data` (or set `DB_PATH`).
4. Set `NODE_ENV=production` and `APP_URL`.
5. Do **not** use Firestore unless you deliberately configure Firebase env vars.

Without a persistent disk, the database is wiped on every deploy.

> **⚠️ Warning:** SQLite on a platform **without** a mounted persistent volume behaves like Cloud Run — existing links return “invalid” after redeploy or sleep. Either attach a volume (`./data`) or use Firestore (GCP only).

---

## 🔒 HTTPS / Reverse Proxy

SecureShare **requires** HTTPS for the Web Crypto API. Managed platforms (Cloud Run, Render, etc.) usually provide TLS automatically.

Behind your own proxy, forward `X-Forwarded-*` headers. Default `TRUST_PROXY=1` suits a single reverse-proxy hop.

### Caddy

```caddyfile
secureshare.yourdomain.com {
    reverse_proxy localhost:3000
}
```

### Nginx

```nginx
server {
    listen 80;
    server_name secureshare.yourdomain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name secureshare.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## ⚙️ Full environment variable reference

| Variable | Default | Used when |
| :--- | :--- | :--- |
| `PORT` | `3000` | Always |
| `NODE_ENV` | — | Set `production` in prod |
| `APP_URL` | — | Production CORS origin |
| `DATABASE_PROVIDER` | auto | `sqlite` (self-host) or `firestore` (GCP) |
| `DB_PATH` | `./data/secrets.db` | SQLite only |
| `TRUST_PROXY` | `1` | Behind load balancer / reverse proxy |
| `FIREBASE_CONFIG` | — | **GCP / Firestore only** — JSON string |
| `FIREBASE_PROJECT_ID`, `FIREBASE_API_KEY`, … | — | **GCP / Firestore only** — alternative to `FIREBASE_CONFIG` |

See [`.env.example`](./.env.example) for a commented template.

---

## Related documentation

- [README — architecture & storage overview](./README.md)
- [Security limitations](./LIMITATIONS.md)
- [Threat model](./THREAT_MODEL.md)
