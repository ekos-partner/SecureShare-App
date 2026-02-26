# Admin Dashboard Guide - SecureShare

The Admin Dashboard is the central command center for managing your SecureShare instance. It allows you to manage administrators, monitor system health, audit actions, and issue API keys for automated integrations.

## 🚀 Accessing the Dashboard

The dashboard is accessible at the `/admin` route of your deployment.

- **URL**: `https://your-domain.com/admin`
- **Default Credentials**: 
    - **Username**: `admin`
    - **Password**: (Set via `ADMIN_PASSWORD` environment variable or the `reset-admin` CLI tool)

### First Login & Security
On your first login, the system will require you to change your initial password. We strongly recommend enabling **Two-Factor Authentication (2FA)** immediately after.

---

## 👥 User Management

SecureShare supports multiple administrative accounts to ensure accountability and prevent single points of failure.

- **Root Administrator**: The primary account (`admin`). It cannot be deleted.
- **Standard Administrators**: Accounts created by other admins. They have full access to the dashboard but can be managed/deleted by others.
- **Password Resets**: Admins can be forced to change their passwords on their next login.

---

## 🔐 Two-Factor Authentication (TOTP)

Protect your administrative accounts with industry-standard TOTP (Time-based One-Time Password).

1. Go to the **Security** tab in the Dashboard.
2. Click **Enable 2FA**.
3. Scan the QR code with an app like **Google Authenticator**, **Microsoft Authenticator**, or **Authy**.
4. Enter the 6-digit verification code to activate.

*Note: If an admin loses their 2FA device, the `reset-admin` CLI tool can be used by someone with server access to reset the account.*

---

## 🔑 API Key Management

API Keys allow external applications (CI/CD pipelines, HR systems, bots) to create secrets programmatically.

### Creating a Key
1. Navigate to the **API Keys** tab.
2. Enter a descriptive name (e.g., "GitHub Actions Prod").
3. **Copy the key immediately**. For security, the raw secret key is shown **only once**.

### Key Format
Keys follow the format: `id.secret_key` (e.g., `a1b2.c3d4e5f6...`). You must provide the full string in the `X-API-Key` header.

---

## 📜 Audit Logs

Transparency is key to security. The **Audit Logs** tab records every significant action:
- Successful and failed login attempts (including IP addresses).
- User creation and deletion.
- API key generation and revocation.
- Security setting changes.

Logs are stored in the local database and are immutable via the web interface.

---

## 🛠️ Emergency Recovery

If you are locked out of the web interface:
1. Access your server's terminal.
2. Run the recovery command:
   ```bash
   npm run reset-admin <username> <new_password>
   ```
This will reset the password, clear failed login attempts, and remove any active lockouts for that user.
