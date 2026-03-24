# Deployment Guide

This guide covers deploying SecureShare to various environments.

## Prerequisites

- Node.js 22+ (if running natively)
- Docker (if running via containers)
- A reverse proxy (Nginx, Caddy, Traefik) for HTTPS termination.

## 🐳 Docker (Recommended)

The easiest and most reliable way to deploy SecureShare is using Docker.

### Using Docker Compose

1. Create a `docker-compose.yml` file:

```yaml
version: '3.8'
services:
  secureshare:
    image: secureshare:latest
    build: .
    ports:
      - "3000:3000"
    volumes:
      - ./data:/app/data
    restart: unless-stopped
    environment:
      - NODE_ENV=production
```

2. Run the container:

```bash
docker compose up -d
```

### Manual Docker Build

```bash
docker build -t secureshare .
docker run -d -p 3000:3000 -v $(pwd)/data:/app/data --name secureshare secureshare
```

## ☁️ Cloud Providers

### Google Cloud Run

1. Build and push the image to Google Container Registry (GCR) or Artifact Registry.
2. Deploy to Cloud Run:
   - Set the container port to `3000`.
   - Mount a Cloud Storage volume to `/app/data` to persist the SQLite database across container restarts.

### Heroku / Render / Railway

1. Connect your GitHub repository.
2. Set the build command to `npm run build`.
3. Set the start command to `npm run start:prod`.
4. **Crucial**: Ensure you attach a persistent disk/volume to `/app/data`. If you don't, your database will be wiped on every deployment or restart.

## 🔒 HTTPS / Reverse Proxy

SecureShare **requires** HTTPS for the Web Crypto API to function correctly in modern browsers. If you are not using a PaaS that provides HTTPS automatically, you must set up a reverse proxy.

### Caddy Example (Easiest)

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

## ⚙️ Environment Variables

- `PORT`: The port the server listens on (default: `3000`).
- `NODE_ENV`: Set to `production` for optimized performance and security headers.
- `DB_PATH`: Override the default SQLite database location (default: `./data/secrets.db`).
