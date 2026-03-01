# 🚀 SecureShare Deployment Guide

This guide covers various scenarios for deploying SecureShare in production environments.

## 🌐 Network Requirements & Configuration

SecureShare is designed to run behind a reverse proxy, which handles SSL termination and routes traffic to the application. The application itself listens on a single port.

| Service | Port | Protocol | Description |
| :--- | :--- | :--- | :--- |
| **Application** | `3000` | HTTP | The internal port SecureShare listens on. **Should NOT be exposed directly to the public internet.** |
| **Reverse Proxy** | `80` | HTTP | Standard port for HTTP traffic. Should redirect to HTTPS. |
| **Reverse Proxy** | `443` | HTTPS | Standard port for secure HTTPS traffic. **REQUIRED for production.** |

**Key Considerations:**
-   **HTTPS is Mandatory**: The Web Crypto API, essential for SecureShare's encryption, requires a secure context (HTTPS or `localhost`). Never deploy to production without HTTPS.
-   **Reverse Proxy**: Always use a reverse proxy (e.g., Nginx, Apache, Cloud Load Balancer) to manage public traffic, handle SSL/TLS termination, and forward requests to the application's internal port (3000).
-   **Firewall Rules**: Configure your firewall to only allow inbound traffic on ports 80 and 443 (for the reverse proxy). All other ports, especially 3000, should be blocked from public access.

---

## 📋 Prerequisites
- Node.js 20+ (for manual installation)
- Docker & Docker Compose (for containerized deployment)
- A domain name (for HTTPS)
- Basic knowledge of terminal/SSH

---

## 1. Manual Installation (Bare Metal / VPS)
Use this if you want to run the app directly on a Linux server (Ubuntu/Debian).

### Step 1: Clone and Install
```bash
git clone <your-repo-url>
cd secureshare
npm install
```

### Step 2: Build Frontend
```bash
npm run build
```

### Step 3: Configure Environment
Create a `.env` file:
```env
PORT=3000
NODE_ENV=production
APP_URL=https://your-domain.com
DB_PATH=./data/secrets.db
```

Ensure the data directory exists: `mkdir -p data`

### Step 4: Run with PM2 (Recommended)
PM2 keeps the app running in the background and restarts it if it crashes.
```bash
npm install -g pm2
pm2 start npm --name "secureshare" -- run start:prod
pm2 save
pm2 startup
```

---

## 2. Docker Deployment with HTTPS (Nginx + Let's Encrypt)
This is the most professional way to deploy on a single VPS.

### Step 1: Docker Compose
Use the provided `docker-compose.yml`. Ensure you have a `data` folder.

### Step 2: Nginx Reverse Proxy
Install Nginx on your host and create a configuration `/etc/nginx/sites-available/secureshare`:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Step 3: SSL Certificate (Certbot)
```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

---

## 3. Google Cloud Platform (GCP) - Cloud Run
Cloud Run is perfect for this app because it scales to zero and handles HTTPS automatically.

### Step 1: Build and Push to Artifact Registry
```bash
gcloud builds submit --tag gcr.io/[PROJECT-ID]/secureshare
```

### Step 2: Deploy to Cloud Run
```bash
gcloud run deploy secureshare \
  --image gcr.io/[PROJECT-ID]/secureshare \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars="APP_URL=https://your-cloud-run-url.a.run.app,NODE_ENV=production"
```

> **Note on Persistence**: Cloud Run filesystems are ephemeral. For a production-grade setup, use **Google Cloud Storage (GCS)** or **Cloud SQL** if you modify the app to use PostgreSQL. For small scale, the `/tmp` fallback works but data is lost on container restart.

---

## 4. Microsoft Azure - App Service
Azure App Service (Web App for Containers) is the easiest path on Azure.

### Step 1: Push to Azure Container Registry (ACR)
```bash
az acr login --name [YOUR_REGISTRY_NAME]
docker tag secureshare [YOUR_REGISTRY_NAME].azurecr.io/secureshare:v1
docker push [YOUR_REGISTRY_NAME].azurecr.io/secureshare:v1
```

### Step 2: Create Web App
1. Go to Azure Portal -> Create a Resource -> Web App.
2. Select **Docker Container** as the Publish method.
3. In the Docker tab, select your ACR image.
4. In **Configuration**, add:
   - `PORT` = `3000`
   - `WEBSITES_PORT` = `3000`
   - `APP_URL` = `https://your-app.azurewebsites.net`
   - `NODE_ENV` = `production`

---

## 📊 System Monitoring & Stats
SecureShare includes a built-in tool to extract system statistics and logs directly from the host or container. This tool accesses the database directly and does not require the web server to be running.

### How to use:

**Traditional Installation (VPS):**
```bash
npm run stats
```

**Docker Installation:**
```bash
docker exec -it <container_id_or_name> npm run stats
```

This will output:
- Total number of secrets in the database.
- Number of expired secrets.
- Total view count across all active secrets.
- System uptime.
- The last 10 system logs (creation, deletion, cleanup events).

---

## 🔐 Security Checklist
1.  **HTTPS**: Never run this app over plain HTTP in production. HSTS is enabled by default.
2.  **Database Permissions**: If running manually, ensure the `secrets.db` file is only readable by the user running the app (`chmod 600 data/secrets.db`).
3.  **Firewall**: Configure your host/cloud firewall to only expose ports 80 and 443 (for the reverse proxy). All other ports, especially 3000, should be blocked from public access.
4.  **Web Application Firewall (WAF)**: Consider implementing a WAF (e.g., Cloudflare, AWS WAF) to protect against common web vulnerabilities (SQL injection, XSS) and manage bot traffic.
5.  **DDoS Protection**: Utilize cloud provider services or specialized solutions for Distributed Denial of Service (DDoS) protection.
6.  **TLS Configuration**: Ensure your reverse proxy is configured with strong, modern TLS cipher suites and protocols. Implement HTTP Strict Transport Security (HSTS).
7.  **Monitoring & Observability**: Implement comprehensive monitoring:
    *   **Application Logs**: Collect and analyze application logs for errors, unusual activity, and security events. Integrate with a SIEM (Security Information and Event Management) system like Splunk, ELK Stack, or cloud-native solutions.
    *   **Network Traffic Analysis**: Monitor network traffic for anomalies, unauthorized access attempts, and data exfiltration.
    *   **System Metrics**: Track CPU, memory, disk I/O, and network usage of your server instances.
    *   **Security Audits**: Regularly perform vulnerability scans, penetration testing, and code audits.
    *   **Rate Limiting**: Monitor and alert on excessive requests to server endpoints, which could indicate brute-force attacks or abuse.
8.  **Review Limitations**: Please read [LIMITATIONS.md](./LIMITATIONS.md) to understand the security model and what this app is NOT designed for.

## 🛠️ Troubleshooting
-   **"Crypto not available"**: Ensure you are accessing the app via `https://` or `localhost`. The Web Crypto API requires a secure context.
-   **Database Locks**: If using SQLite on a network file system (NFS/EFS), you might encounter locking issues. Use a local volume or switch to PostgreSQL (requires code changes).
