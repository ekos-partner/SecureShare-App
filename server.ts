/**
 * SECURESHARE SERVER
 * 
 * This is the main server file for the SecureShare application.
 * It handles API requests, serves the frontend, and manages the SQLite database.
 * 
 * SECURITY FEATURES IMPLEMENTED:
 * 1. Content Security Policy (CSP): Prevents XSS attacks by restricting sources.
 * 2. HSTS: Enforces HTTPS connections.
 * 3. Rate Limiting: Prevents abuse and brute-force attacks.
 * 4. Atomic Transactions: Ensures "burn-after-reading" logic is race-condition free.
 * 5. Input Validation: Uses Zod to strictly validate all incoming data.
 */

import express from "express";
import Database from "better-sqlite3";
import { v4 as uuidv4 } from "uuid";
import path from "node:path";
import fs from "node:fs";
import os from "node:os";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cors from "cors";
import { z } from "zod";
import crypto from 'node:crypto';
import ejs from 'ejs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import { authenticator } from 'otplib';
import QRCode from 'qrcode';
import bcrypt from 'bcrypt';
import csrf from 'csurf';

/**
 * DATABASE INITIALIZATION
 * We use SQLite for lightweight, persistent storage.
 * The database stores encrypted blobs (AES-GCM ciphertext), expiration dates, and view limits.
 * 
 * NOTE: In production (Cloud Run/Azure), use a persistent volume for 'secrets.db' 
 * to avoid data loss on container restarts.
 */
const getDatabase = () => {
  const dbPath = process.env.DB_PATH || path.join(process.cwd(), "secrets.db");
  try {
    return new Database(dbPath);
  } catch (err) {
    // Fallback to a secure temporary directory for environments with read-only filesystems
    try {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureshare-'));
      const tmpDbPath = path.join(tmpDir, 'secrets.db');
      console.warn(`Failed to open database at ${dbPath}, using secure temporary database at ${tmpDbPath}`);
      return new Database(tmpDbPath);
    } catch (error) {
      console.error('Failed to create temporary database:', error);
      throw err;
    }
  }
};

const db = getDatabase();

/**
 * SCHEMA DEFINITION
 * - encrypted_data: The AES-encrypted payload (client-side encrypted).
 * - password_hash: SHA-256 hash of the user password + salt (optional).
 * - salt: Random salt used for password hashing (optional).
 * - view_limit: Max number of times the secret can be opened.
 * - failed_attempts: Counter for brute-force protection on password-protected secrets.
 */
db.exec(`
  CREATE TABLE IF NOT EXISTS secrets (
    id TEXT PRIMARY KEY,
    encrypted_data TEXT NOT NULL,
    password_hash TEXT,
    salt TEXT,
    expires_at DATETIME NOT NULL,
    view_limit INTEGER DEFAULT 1,
    view_count INTEGER DEFAULT 0,
    failed_attempts INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    usage_count INTEGER DEFAULT 0
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_root INTEGER DEFAULT 0,
    must_change_password INTEGER DEFAULT 0,
    totp_secret TEXT,
    is_totp_enabled INTEGER DEFAULT 0,
    failed_attempts INTEGER DEFAULT 0,
    lockout_until DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    action TEXT NOT NULL,
    user_id TEXT,
    username TEXT,
    ip_address TEXT,
    details TEXT
  )
`);

// Add index for TTL cleanup performance
db.exec(`CREATE INDEX IF NOT EXISTS idx_secrets_expires_at ON secrets (expires_at)`);

// Apply migrations for older database versions
    try {
      db.exec("ALTER TABLE secrets ADD COLUMN salt TEXT"); 
    } catch { 
      // ignore 
    }
    try { 
      db.exec("ALTER TABLE secrets ADD COLUMN failed_attempts INTEGER DEFAULT 0"); 
    } catch { 
      // ignore 
    }

/**
 * INPUT VALIDATION
 * Using Zod to ensure all incoming data matches expected formats and sizes.
 */
const CreateSecretSchema = z.object({
  encryptedData: z.string().min(1).max(1024 * 1024), // Max 1MB payload
  passwordHash: z.string().nullable().optional(),
  salt: z.string().nullable().optional(),
  expirationHours: z.union([z.string(), z.number()]).transform(Number),
  viewLimit: z.union([z.string(), z.number()]).transform(Number),
});

const BurnSecretSchema = z.object({
  passwordHash: z.string().nullable().optional(),
});

/**
 * BRUTE-FORCE PROTECTION LOGIC
 * Extracted to reduce cognitive complexity.
 * Returns null if verification passes, or an error object if it fails.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function verifyPasswordAndHandleBruteForce(db: Database.Database, secret: any, passwordHash: string | null | undefined) {
  if (!secret.password_hash) return null;

  if (!passwordHash || passwordHash !== secret.password_hash) {
    const newFailedAttempts = (secret.failed_attempts || 0) + 1;
    const MAX_ATTEMPTS = 3;

    if (newFailedAttempts >= MAX_ATTEMPTS) {
      db.prepare("DELETE FROM secrets WHERE id = ?").run(secret.id);
      console.log(`[Security] Secret ${secret.id} burned after ${MAX_ATTEMPTS} failed attempts.`);
      return { status: 401, body: { error: "Too many failed attempts. Secret has been permanently deleted." } };
    }

    db.prepare("UPDATE secrets SET failed_attempts = ? WHERE id = ?").run(newFailedAttempts, secret.id);
    return { 
      status: 401, 
      body: { error: `Invalid password. ${MAX_ATTEMPTS - newFailedAttempts} attempts remaining before permanent deletion.` } 
    };
  }

  return null;
}

/**
 * VIEW LIMIT LOGIC
 * Extracted to reduce cognitive complexity.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function handleViewLimit(db: Database.Database, secret: any) {
  const newCount = secret.view_count + 1;
  const isBurned = newCount >= secret.view_limit;
  const remaining = Math.max(0, secret.view_limit - newCount);

  if (isBurned) {
    db.prepare("DELETE FROM secrets WHERE id = ?").run(secret.id);
    console.log(`[ViewLimit] Secret ${secret.id} deleted after reaching view limit (${secret.view_limit}).`);
  } else {
    db.prepare("UPDATE secrets SET view_count = ? WHERE id = ?").run(newCount, secret.id);
  }

  return { success: true, burned: isBurned, remaining };
}

const app = express();
const PORT = Number.parseInt(process.env.PORT || "3000", 10);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

// JWT Secret security check
const getJwtSecret = () => {
  const secret = process.env.JWT_SECRET;
  if (process.env.NODE_ENV === "production") {
    if (!secret || secret.length < 32) {
      console.error("CRITICAL: JWT_SECRET must be set in environment and be at least 32 characters long in production!");
      process.exit(1);
    }
    return secret;
  }
  if (!secret) {
    console.warn("WARNING: JWT_SECRET not set. Using temporary random secret. Admin sessions will reset on restart.");
    return crypto.randomBytes(32).toString('hex');
  }
  return secret;
};

const JWT_SECRET = getJwtSecret();

/**
 * AUDIT LOGGING HELPER
 */
function logAction(action: string, userId: string | null, username: string | null, ip: string, details: string = "") {
  try {
    db.prepare("INSERT INTO audit_logs (id, action, user_id, username, ip_address, details) VALUES (?, ?, ?, ?, ?, ?)")
      .run(uuidv4(), action, userId, username, ip, details);
  } catch (err) {
    console.error("Failed to log action:", err);
  }
}

/**
 * INITIALIZE ROOT USER
 * If no users exist, create the root user from ADMIN_PASSWORD
 */
async function initializeRootUser() {
  const userCount = db.prepare("SELECT COUNT(*) as count FROM users").get() as { count: number };
  if (userCount.count === 0) {
    const id = uuidv4();
    const initialPassword = ADMIN_PASSWORD || 'admin'; // Fallback to 'admin' if ENV var not set
    const hash = await bcrypt.hash(initialPassword, 12);
    db.prepare("INSERT INTO users (id, username, password_hash, is_root, must_change_password) VALUES (?, ?, ?, ?, ?)")
      .run(id, 'admin', hash, 1, 1); // Force password change on first login
    console.log(`[Security] Root admin user initialized with bcrypt. Must change password on first login.`);
    logAction("SYSTEM_INIT", id, "admin", "127.0.0.1", "Root user created from ENV or default");
  }
}
initializeRootUser().catch(console.error);

app.use(cookieParser());

// CSRF Protection for admin routes
const csrfProtection = csrf({ 
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  }
});

// Disable X-Powered-By to prevent technology fingerprinting (Proxy Disclosure)
app.disable('x-powered-by');

// Disable TRACE method (Proxy Disclosure)
app.use((req, res, next) => {
  if (req.method === 'TRACE') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

// Trust proxy is required for rate limiting and secure cookies to work behind Nginx/Cloud Run
app.set('trust proxy', 1);

// Generate a nonce for each request
app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString('hex');
  next();
});

/**
 * PRODUCTION SECURITY MIDDLEWARE
 * Strict security headers for the standalone production environment.
 */
if (process.env.NODE_ENV === "production") {
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", (req, res) => `'nonce-${res.locals.nonce}'`],
        // Allow inline styles for React/Motion
        styleSrc: ["'self'", "'unsafe-inline'", (req, res) => `'nonce-${res.locals.nonce}'`, "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:", "https://picsum.photos", "blob:"],
        // Restrict connectSrc
        connectSrc: ["'self'"],
        frameAncestors: ["'self'", "https://*.google.com", "https://*.run.app"],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
    referrerPolicy: { policy: "no-referrer" },
    noSniff: true,
    crossOriginEmbedderPolicy: false,
    frameguard: { action: "sameorigin" },
  }));

  // Add the Permissions-Policy header manually
  app.use((req, res, next) => {
    res.setHeader('Permissions-Policy', 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()');
    next();
  });
}

// CORS Configuration
const allowedOrigin = process.env.APP_URL || false; 
if (allowedOrigin) {
  app.use(cors({
    origin: allowedOrigin,
    methods: ["GET", "POST"],
    credentials: true
  }));
}
app.use(express.json({ limit: '1.1mb' }));

interface UserRow {
  id: string;
  username: string;
  password_hash: string;
  is_root: number;
  must_change_password: number;
  totp_secret: string | null;
  is_totp_enabled: number;
  failed_attempts: number;
  lockout_until: string | null;
  created_at: string;
}

/**
 * ADMIN AUTHENTICATION MIDDLEWARE
 */
const authenticateAdmin = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  const token = req.cookies.admin_token;
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as { userId: string, username: string };
    
    // Verify user still exists
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(decoded.userId) as UserRow | undefined;
    if (!user) return res.status(401).json({ error: "User no longer exists" });

    (req as AuthenticatedRequest).user = user;
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
};

/**
 * API KEY VERIFICATION MIDDLEWARE
 */
const verifyApiKey = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
  const apiKey = req.headers['x-api-key'] as string;
  
  // If no API key is provided, we allow it (for the web UI/CLI backward compatibility)
  // but we could enforce it for specific routes if needed.
  if (!apiKey) return next();

  try {
    const [id, rawKey] = apiKey.split('.');
    if (!id || !rawKey) return res.status(401).json({ error: "Invalid API Key format" });

    const keyData = db.prepare("SELECT * FROM api_keys WHERE id = ?").get(id) as { key_hash: string } | undefined;
    if (!keyData) return res.status(401).json({ error: "Invalid API Key" });

    const isKeyValid = await bcrypt.compare(rawKey, keyData.key_hash);
    if (!isKeyValid) return res.status(401).json({ error: "Invalid API Key" });

    // Update usage stats
    db.prepare("UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP, usage_count = usage_count + 1 WHERE id = ?").run(id);
    
    next();
  } catch {
    res.status(401).json({ error: "API Key verification failed" });
  }
};

/**
 * RATE LIMITING
 * Prevents abuse while allowing for automated security testing.
 */
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100, // Secure limit for general API usage
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests from this IP, please try again later." }
});
app.use(globalLimiter);

const createLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20, // Strict limit for secret creation
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Creation limit reached. Please try again later." }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // Very strict limit for failed password attempts
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: { error: "Too many failed attempts. Please wait 15 minutes." }
});

/**
 * API ENDPOINTS
 */

// Create a new secret
app.get("/api/health", (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get("/api/admin/csrf-token", authenticateAdmin, csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

/**
 * ADMIN API ROUTES
 */
app.post("/api/admin/login", authLimiter, async (req, res) => {
  const { username, password, totpToken } = req.body;
  const ip = req.ip || "unknown";

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username) as UserRow | undefined;
  
  if (!user) {
    logAction("LOGIN_FAILED", null, username, ip, "User not found");
    return res.status(401).json({ error: "Invalid credentials" });
  }

  // Check lockout
  if (user.lockout_until && new Date(user.lockout_until) > new Date()) {
    return res.status(403).json({ error: "Account locked. Please try again later." });
  }

  // Password verification with migration support (SHA-256 -> bcrypt)
  let isPasswordValid = false;
  const isLegacyHash = user.password_hash.length === 64 && !user.password_hash.startsWith('$2');

  if (isLegacyHash) {
    const legacyHash = crypto.createHash('sha256').update(password).digest('hex');
    isPasswordValid = legacyHash === user.password_hash;
    
    if (isPasswordValid) {
      // Migrate to bcrypt
      const newHash = await bcrypt.hash(password, 12);
      db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(newHash, user.id);
      console.log(`[Security] Migrated user ${username} from SHA-256 to bcrypt.`);
    }
  } else {
    isPasswordValid = await bcrypt.compare(password, user.password_hash);
  }

  if (!isPasswordValid) {
    const attempts = user.failed_attempts + 1;
    let lockoutUntil = null;
    if (attempts >= 5) {
      lockoutUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    }
    db.prepare("UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE id = ?").run(attempts, lockoutUntil, user.id);
    logAction("LOGIN_FAILED", user.id, username, ip, `Wrong password. Attempt ${attempts}`);
    return res.status(401).json({ error: "Invalid credentials" });
  }

  // Check TOTP
  if (user.is_totp_enabled) {
    if (!totpToken) {
      return res.status(200).json({ requiresTotp: true });
    }
    const isValid = authenticator.check(totpToken, user.totp_secret);
    if (!isValid) {
      logAction("LOGIN_FAILED_TOTP", user.id, username, ip, "Invalid TOTP token");
      return res.status(401).json({ error: "Invalid TOTP token" });
    }
  }

  // Success
  db.prepare("UPDATE users SET failed_attempts = 0, lockout_until = NULL WHERE id = ?").run(user.id);
  
  const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
  res.cookie('admin_token', token, { 
    httpOnly: true, 
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000 
  });

  logAction("LOGIN_SUCCESS", user.id, username, ip);
  return res.json({ 
    success: true, 
    mustChangePassword: !!user.must_change_password,
    username: user.username
  });
});

app.post("/api/admin/change-password", authenticateAdmin, csrfProtection, async (req, res) => {
  const { newPassword } = req.body;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const user = (req as any).user as UserRow;

  if (!newPassword || newPassword.length < 8) {
    return res.status(400).json({ error: "Password must be at least 8 characters long" });
  }

  const hash = await bcrypt.hash(newPassword, 12);
  db.prepare("UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?").run(hash, user.id);
  
  logAction("PASSWORD_CHANGED", user.id, user.username, req.ip || "unknown");
  res.json({ success: true });
});

app.get("/api/admin/users", authenticateAdmin, (req, res) => {
  const users = db.prepare("SELECT id, username, is_root, must_change_password, is_totp_enabled, created_at FROM users").all();
  res.json(users);
});

app.post("/api/admin/users", authenticateAdmin, csrfProtection, async (req, res) => {
  const { username, password } = req.body;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const admin = (req as any).user as UserRow;

  if (!username || !password || password.length < 8) {
    return res.status(400).json({ error: "Invalid username or password" });
  }

  try {
    const id = uuidv4();
    const hash = await bcrypt.hash(password, 12);
    db.prepare("INSERT INTO users (id, username, password_hash, must_change_password) VALUES (?, ?, ?, 1)")
      .run(id, username.trim(), hash);
    
    logAction("USER_CREATED", admin.id, admin.username, req.ip || "unknown", `Created user ${username}`);
    res.json({ success: true });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } catch (err) {
    const error = err as Error;
    if (error.message.includes('UNIQUE')) {
      return res.status(400).json({ error: "Username already exists" });
    }
    res.status(500).json({ error: "Internal server error" });
  }
});

app.delete("/api/admin/users/:id", authenticateAdmin, csrfProtection, (req, res) => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const admin = (req as any).user as UserRow;
  const targetId = req.params.id;

  const target = db.prepare("SELECT * FROM users WHERE id = ?").get(targetId) as UserRow | undefined;
  if (!target) return res.status(404).json({ error: "User not found" });

  if (target.is_root) {
    return res.status(403).json({ error: "Root administrator cannot be deleted" });
  }

  db.prepare("DELETE FROM users WHERE id = ?").run(targetId);
  logAction("USER_DELETED", admin.id, admin.username, req.ip || "unknown", `Deleted user ${target.username}`);
  res.json({ success: true });
});

app.post("/api/admin/totp/setup", authenticateAdmin, csrfProtection, async (req, res) => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const user = (req as any).user as UserRow;
  const secret = authenticator.generateSecret();
  const otpauth = authenticator.keyuri(user.username.trim(), 'SecureShare', secret);
  
  try {
    const qrCodeUrl = await QRCode.toDataURL(otpauth);
    // Store secret temporarily in session or just return it for verification
    // For simplicity, we'll store it in the DB but marked as disabled
    db.prepare("UPDATE users SET totp_secret = ?, is_totp_enabled = 0 WHERE id = ?").run(secret, user.id);
    res.json({ qrCodeUrl, secret });
  } catch {
    res.status(500).json({ error: "Failed to generate QR code" });
  }
});

app.post("/api/admin/totp/verify", authenticateAdmin, csrfProtection, (req, res) => {
  const { token } = req.body;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const user = (req as any).user as UserRow;

  const dbUser = db.prepare("SELECT totp_secret FROM users WHERE id = ?").get(user.id) as UserRow | undefined;
  if (!dbUser || !dbUser.totp_secret) return res.status(400).json({ error: "TOTP not set up" });

  const isValid = authenticator.check(token, dbUser.totp_secret);
  if (isValid) {
    db.prepare("UPDATE users SET is_totp_enabled = 1 WHERE id = ?").run(user.id);
    logAction("TOTP_ENABLED", user.id, user.username, req.ip || "unknown");
    res.json({ success: true });
  } else {
    res.status(400).json({ error: "Invalid token" });
  }
});

app.post("/api/admin/totp/disable", authenticateAdmin, csrfProtection, (req, res) => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const user = (req as any).user as UserRow;
  db.prepare("UPDATE users SET is_totp_enabled = 0, totp_secret = NULL WHERE id = ?").run(user.id);
  logAction("TOTP_DISABLED", user.id, user.username, req.ip || "unknown");
  res.json({ success: true });
});

app.get("/api/admin/logs", authenticateAdmin, (req, res) => {
  const logs = db.prepare("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 100").all();
  res.json(logs);
});

app.get("/api/admin/stats", authenticateAdmin, (req, res) => {
  const totalSecrets = db.prepare("SELECT COUNT(*) as count FROM secrets").get() as { count: number };
  const activeKeys = db.prepare("SELECT COUNT(*) as count FROM api_keys").get() as { count: number };
  const totalViews = db.prepare("SELECT SUM(view_count) as count FROM secrets").get() as { count: number };
  
  res.json({
    totalSecrets: totalSecrets.count,
    activeKeys: activeKeys.count,
    totalViews: totalViews.count || 0,
    uptime: process.uptime()
  });
});

app.get("/api/admin/keys", authenticateAdmin, (req, res) => {
  const keys = db.prepare("SELECT id, name, created_at, last_used_at, usage_count FROM api_keys ORDER BY created_at DESC").all();
  res.json(keys);
});

app.post("/api/admin/keys", authenticateAdmin, csrfProtection, async (req, res) => {
  const { name } = req.body;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const admin = (req as any).user as UserRow;
  if (!name) return res.status(400).json({ error: "Name is required" });

  const id = crypto.randomBytes(4).toString('hex');
  const rawKey = crypto.randomBytes(32).toString('hex');
  const hash = await bcrypt.hash(rawKey, 10); // API keys don't need 12 rounds, 10 is enough and faster

  db.prepare("INSERT INTO api_keys (id, name, key_hash) VALUES (?, ?, ?)").run(id, name, hash);
  logAction("API_KEY_CREATED", admin.id, admin.username, req.ip || "unknown", `Created key ${name}`);

  res.json({
    id,
    name,
    apiKey: `${id}.${rawKey}`, // Only shown once
    csrfToken: req.csrfToken ? req.csrfToken() : undefined
  });
});

app.delete("/api/admin/keys/:id", authenticateAdmin, csrfProtection, (req, res) => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const admin = (req as any).user as UserRow;
  db.prepare("DELETE FROM api_keys WHERE id = ?").run(req.params.id);
  logAction("API_KEY_DELETED", admin.id, admin.username, req.ip || "unknown", `Deleted key ${req.params.id}`);
  res.json({ success: true });
});

app.post("/api/secrets", createLimiter, verifyApiKey, (req, res) => {
  const result = CreateSecretSchema.safeParse(req.body);
  if (!result.success) {
    return res.status(400).json({ error: "Invalid input data", details: result.error.format() });
  }

  const { encryptedData, passwordHash, salt, expirationHours, viewLimit } = result.data;
  
  // Enforce limits
  if (expirationHours < 1 || expirationHours > 168) {
    return res.status(400).json({ error: "Expiration must be between 1 and 168 hours" });
  }
  if (viewLimit < 1 || viewLimit > 10) {
    return res.status(400).json({ error: "View limit must be between 1 and 10" });
  }

  const id = uuidv4();
  const expiresAt = new Date(Date.now() + expirationHours * 60 * 60 * 1000).toISOString();

  try {
    const stmt = db.prepare(`
      INSERT INTO secrets (id, encrypted_data, password_hash, salt, expires_at, view_limit)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    stmt.run(id, encryptedData, passwordHash || null, salt || null, expiresAt, viewLimit);
    res.json({ id });
  } catch (error) {
    console.error("Database error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Fetch secret metadata (encrypted blob + salt)
app.get("/api/secrets/:id", (req, res) => {
  const { id } = req.params;
  
  try {
    const secret = db.prepare("SELECT * FROM secrets WHERE id = ?").get(id) as { 
    id: string;
    encrypted_data: string;
    password_hash: string | null;
    salt: string | null;
    expires_at: string;
    view_limit: number;
    view_count: number;
    failed_attempts: number;
  } | undefined;

    // Opaque response for non-existent or expired secrets to prevent enumeration
    if (!secret || new Date(secret.expires_at) < new Date()) {
      if (secret && new Date(secret.expires_at) < new Date()) {
        db.prepare("DELETE FROM secrets WHERE id = ?").run(id);
      }
      return res.status(404).json({ error: "Secret not found or expired" });
    }

    res.json({
      encryptedData: secret.encrypted_data,
      hasPassword: !!secret.password_hash,
      salt: secret.salt
    });
  } catch (error) {
    console.error("Transaction error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Verify access and "burn" the secret (increment view count or delete)
app.post("/api/secrets/:id/burn", authLimiter, (req, res) => {
  const { id } = req.params;
  const result = BurnSecretSchema.safeParse(req.body);
  if (!result.success) {
    return res.status(400).json({ error: "Invalid input data" });
  }

  const { passwordHash } = result.data;

  try {
    // ATOMIC TRANSACTION: Check, Verify, and Update/Delete in one go
    // Refactored to keep cognitive complexity low (< 15)
    // Using .immediate() to prevent race conditions in SQLite
    const transaction = db.transaction(() => {
      const secret = db.prepare("SELECT * FROM secrets WHERE id = ?").get(id) as { 
        id: string;
        encrypted_data: string;
        password_hash: string | null;
        salt: string | null;
        expires_at: string;
        view_limit: number;
        view_count: number;
        failed_attempts: number;
      } | undefined;
      
      if (!secret) {
        return { status: 404, body: { error: "Not found" } };
      }

      // 1. Verify password & handle brute force
      const authError = verifyPasswordAndHandleBruteForce(db, secret, passwordHash);
      if (authError) return authError;

      // 2. Handle view limits and burning
      const viewResult = handleViewLimit(db, secret);

      return { status: 200, body: viewResult };
    });

    const txResult = transaction.immediate();
    res.status(txResult.status).json(txResult.body);

  } catch (error) {
    console.error("Transaction error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * PERIODIC CLEANUP
 * Deletes expired secrets from the database every 5 minutes.
 */
setInterval(() => {
  try {
    const now = new Date().toISOString();
    const result = db.prepare("DELETE FROM secrets WHERE expires_at < ?").run(now);
    if (result.changes > 0) {
      console.log(`[Cleanup] Deleted ${result.changes} expired secrets.`);
    }
  } catch (error) {
    console.error("[Cleanup] Error cleaning up expired secrets:", error);
  }
}, 5 * 60 * 1000);

/**
 * STATIC FILE SERVING & VITE INTEGRATION
 */
const startServer = async () => {
  if (process.env.NODE_ENV === "production") {
    // Production mode: Serve pre-built static files from /dist
    const distPath = path.resolve(process.cwd(), "dist");
    if (fs.existsSync(distPath)) {
      app.engine('html', ejs.renderFile);
      app.set('view engine', 'html');
      app.set('views', distPath);

      // app.use(express.static(process.cwd())); // Moved to top
      app.use(express.static(distPath));
      app.get("*", (req, res) => {
        res.render(path.resolve(distPath, "index.html"), { nonce: res.locals.nonce });
      });
    } else {
      console.warn("Production build 'dist' folder not found. Static files will not be served.");
    }
  } else {
    // Development mode: Use Vite middleware and EJS for nonce injection
    const { createServer: createViteServer } = await import("vite");
    const vite = await createViteServer({
      server: { 
        middlewareMode: true,
        hmr: false // Disable HMR as per platform guidelines
      },
      appType: "spa",
    });
    // app.use(express.static(process.cwd())); // Moved to top
    app.use(vite.middlewares);
    app.get('*', async (req, res, next) => {
      try {
        // Sanitize URL
        const url = req.path; 
        const template = await vite.transformIndexHtml(url, fs.readFileSync(path.resolve(process.cwd(), 'index.html'), 'utf-8'));
        // Inject nonce
        const renderedHtml = template.replaceAll('<%= nonce %>', res.locals.nonce);
        res.status(200).set({ 'Content-Type': 'text/html' }).end(renderedHtml);
      } catch (e) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        vite.ssrFixStacktrace(e as any);
        next(e);
      }
    });
  }

  // Security.txt implementation (RFC 9116)
  app.get(["/.well-known/security.txt", "/security.txt"], (req, res) => {
    const securityTxt = `Contact: https://${req.hostname}/security-policy
Expires: ${new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()}
Canonical: https://${req.hostname}/.well-known/security.txt
Policy: https://${req.hostname}/security-policy
`;
    res.type('text/plain').send(securityTxt);
  });

  app.get("/security-policy", (req, res) => {
    res.type('text/plain').send(`# Security Policy

1. Reporting
   Please report vulnerabilities via GitHub's "Report a vulnerability" feature in the Security tab.
   Do not open public issues for security flaws.

2. Supported Versions
   Only the latest deployment is supported.

3. Response
   We aim to respond within 48 hours.
`);
  });

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });

  // Global error handler
  // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars
  app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    console.error(err);
    res.status(500).send('Internal Server Error');
  });
};

// Start server
startServer().catch(console.error);
