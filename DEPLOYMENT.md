# Deployment Guide

This guide covers deploying SecureShare to various environments.

## Prerequisites

- Node.js 22+ (if running natively)
- Docker (recommended for self-hosted)
- A reverse proxy (Nginx, Caddy, Traefik) for HTTPS termination when not using a managed platform

## 🗄️ Choosing a Storage Backend

SecureShare selects the database at startup via `database-provider.ts`:

| Backend | Typical deployment | Selection |
| :--- | :--- | :--- |
| **SQLite** (default) | Docker, VPS, single-instance PaaS | No Firebase config, or `DATABASE_PROVIDER=sqlite` |
| **Cloud Firestore** | GCP Cloud Run (serverless, scale-to-zero) | Valid `firebase-applet-config.json`, or `DATABASE_PROVIDER=firestore` |

- **SQLite** persists encrypted blobs in a local file (`data/secrets.db` by default). Use a volume mount so data survives container restarts.
- **Firestore** stores secrets in Google Cloud Firestore. No shared disk is required; ideal for Cloud Run with multiple instances or scale-to-zero.
- **`firebase-applet-config.json`** must contain real `projectId` and `apiKey` values (no `placeholder` strings). The file is **gitignored** — inject it at deploy time (Secret Manager, mounted volume, etc.), never commit it.

Deploy Firestore security rules from the repository before going live:

```bash
firebase deploy --only firestore:rules
```

(Uses `firestore.rules` in this repo.)

---

## 🐳 Docker (Recommended for Self-Hosted)

The repository includes a `docker-compose.yml` for local or VPS deployment with **SQLite**.

```bash
docker compose up -d
```

This mounts `./data` → `/app/data` and uses the default SQLite path (`/app/data/secrets.db` in the image).

### Manual Docker Build

```bash
docker build -t secureshare .
docker run -d -p 3000:3000 -v "$(pwd)/data:/app/data" \
  -e NODE_ENV=production \
  -e APP_URL=https://your-domain.example \
  --name secureshare secureshare
```

> **Firestore in Docker**: Mount `firebase-applet-config.json` into the container working directory and set `DATABASE_PROVIDER=firestore`, or rely on auto-detection when the config file is present and valid.

---

## ☁️ Google Cloud Platform

### Option A — Cloud Run + Firestore (recommended on GCP)

Best when you want serverless scaling, no persistent disk, and secrets stored in Firestore.

1. **Firebase / Firestore**
   - Create or use an existing Firebase project with Firestore enabled.
   - Note the **database ID** (if using a named database, not `(default)`).
   - Deploy rules: `firebase deploy --only firestore:rules`.

2. **Client config** (local only, never in Git)
   - Create `firebase-applet-config.json` in the project root with fields such as:
     - `projectId`, `appId`, `apiKey`, `authDomain`, `firestoreDatabaseId`, `storageBucket`, `messagingSenderId`
   - Obtain values from the Firebase console or your AI Studio / applet export.

3. **Container image**
   - Build and push to **Artifact Registry** (or GCR):

   ```bash
   gcloud builds submit --tag REGION-docker.pkg.dev/PROJECT_ID/REPO/secureshare:latest
   ```

4. **Cloud Run service**
   - Container port: **3000**
   - Environment variables:
     - `NODE_ENV=production`
     - `DATABASE_PROVIDER=firestore` (recommended; explicit)
     - `APP_URL=https://YOUR_CLOUD_RUN_URL` (public HTTPS URL of the service)
   - **Secrets**: Store `firebase-applet-config.json` in **Secret Manager** and mount it as a file at `/app/firebase-applet-config.json`, *or* bake it into a private image layer (less ideal).
   - **No** Cloud Storage volume is required for the database.
   - Ensure the service account used by Cloud Run can access Firestore (Firebase Admin is not required — the app uses the Firebase Web SDK with your config; lock down API keys in Google Cloud Console).

5. **HTTPS**: Cloud Run provides HTTPS automatically. `TRUST_PROXY` defaults to `1`, which suits Cloud Run’s load balancer.

### Option B — Cloud Run + SQLite + Cloud Storage volume

Use when you prefer a single SQLite file instead of Firestore.

1. Create a **Cloud Storage bucket** and mount it to the container (Cloud Storage FUSE), e.g. at `/data`.
2. Set environment variables:
   - `DATABASE_PROVIDER=sqlite`
   - `DB_PATH=/data/secrets.db` (paths under `/data` or containing `secureshare-storage-db` enable GCS FUSE mirroring in code)
   - `NODE_ENV=production`
   - `APP_URL=https://YOUR_CLOUD_RUN_URL`
3. Deploy to Cloud Run with the volume attached so the DB file persists across revisions.

> **Note**: SQLite on Cloud Run works for low concurrency. For higher traffic or many concurrent instances, **Firestore (Option A)** avoids file locking and shared-disk limitations.

### Build & deploy summary (GCP)

```bash
# Example: build with Cloud Build
gcloud builds submit --tag REGION-docker.pkg.dev/PROJECT_ID/secureshare/secureshare:latest

# Example: deploy (set env vars and secrets in console or via YAML)
gcloud run deploy secureshare \
  --image REGION-docker.pkg.dev/PROJECT_ID/secureshare/secureshare:latest \
  --port 3000 \
  --set-env-vars NODE_ENV=production,DATABASE_PROVIDER=firestore,APP_URL=https://YOUR_URL \
  --set-secrets /app/firebase-applet-config.json=firebase-applet-config:latest
```

Adjust secret mount syntax to your project’s Secret Manager setup.

---

## Other Cloud Providers (Heroku / Render / Railway)

These platforms typically map to the **SQLite** backend:

1. Connect the GitHub repository.
2. Build: `npm run build`
3. Start: `npm run start:prod`
4. Attach a **persistent disk/volume** at `/app/data` (or set `DB_PATH` to the mounted path).
5. Set `NODE_ENV=production` and `APP_URL` to your public HTTPS URL.
6. Do **not** rely on ephemeral filesystem — without a volume, `secrets.db` is lost on every deploy.

For Firestore on generic PaaS, mount `firebase-applet-config.json` and set `DATABASE_PROVIDER=firestore` if the platform supports file secrets.

---

## 🔒 HTTPS / Reverse Proxy

SecureShare **requires** HTTPS for the Web Crypto API in modern browsers. Managed platforms (Cloud Run, Render, etc.) usually terminate TLS for you.

Behind your own reverse proxy, forward `X-Forwarded-*` headers and keep `TRUST_PROXY` at `1` (default) for a single hop.

### Caddy Example

```caddyfile
secureshare.yourdomain.com {
    reverse_proxy localhost:3000
}
```

### Nginx Example

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

## ⚙️ Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PORT` | `3000` | HTTP port |
| `NODE_ENV` | — | Set to `production` for security headers and production behavior |
| `APP_URL` | — | Public origin (e.g. `https://share.example.com`) for CORS in production |
| `DATABASE_PROVIDER` | auto | `sqlite` or `firestore`; overrides auto-detection |
| `DB_PATH` | `./data/secrets.db` | SQLite file path only; GCS FUSE paths trigger mirror mode |
| `TRUST_PROXY` | `1` | Express `trust proxy` setting (`true`, `false`, number, or hop count) |

---

## Related Documentation

- [README — Storage backends & architecture](./README.md)
- [Release Notes](./RELEASE_NOTES.md)
- [Security Limitations](./LIMITATIONS.md)
- [Threat Model](./THREAT_MODEL.md)
