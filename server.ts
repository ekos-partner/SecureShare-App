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
import cookieParser from 'cookie-parser';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const jwt = require('jsonwebtoken');
const otplib = require('otplib');
const authenticator = otplib.authenticator || otplib;

// Configure authenticator options
authenticator.options = { 
  window: [1, 1] // Allow for slight time drift (1 step = 30s before and after)
};
console.log("2FA Authenticator initialized successfully.");

const QRCode = require('qrcode');
const bcrypt = require('bcrypt');
const csrf = require('csurf');

/**
 * DATABASE INITIALIZATION
 * We use SQLite for lightweight, persistent storage.
 * The database stores encrypted blobs (AES-GCM ciphertext), expiration dates, and view limits.
 * 
 * NOTE: In production (Cloud Run/Azure), use a persistent volume for 'secrets.db' 
 * to avoid data loss on container restarts.
 */
const getDatabase = () => {
  // In production environments like Cloud Run, we prefer a path that might be mapped to a volume
  // or at least a consistent location.
  const dbPath = process.env.DB_PATH || path.join(process.cwd(), "data", "secrets.db");
  
  // Ensure the directory exists
  const dbDir = path.dirname(dbPath);
  if (!fs.existsSync(dbDir)) {
    try {
      fs.mkdirSync(dbDir, { recursive: true });
    } catch {
      console.warn(`Failed to create directory ${dbDir}, falling back to temp storage`);
    }
  }

  try {
    return new Database(dbPath);
  } catch {
    // Fallback to a secure temporary directory for environments with read-only filesystems
    try {
      const tmpDbPath = path.join(os.tmpdir(), 'secureshare-secrets.db');
      console.warn(`Failed to open database at ${dbPath}, using temporary database at ${tmpDbPath}. DATA WILL BE LOST ON RESTART.`);
      return new Database(tmpDbPath);
    } catch (error) {
      console.error('Failed to create temporary database:', error);
      throw new Error(`Could not open database at ${dbPath} and failed to create fallback.`);
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
    backup_codes TEXT,
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

db.exec(`
  CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    public_key BLOB NOT NULL,
    counter INTEGER NOT NULL,
    transports TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id TEXT PRIMARY KEY,
    challenge TEXT NOT NULL,
    user_id TEXT,
    expires_at DATETIME NOT NULL
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
  powNonce: z.string().optional(),
  powSalt: z.string().optional(),
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
  // Always use a random secret if not provided, even in dev, to prevent predictable tokens
  if (!secret || secret === "dev-secret-key-change-this-in-prod") {
    if (process.env.NODE_ENV === "production") {
      console.error("CRITICAL: JWT_SECRET must be set in environment in production!");
    }
    // Use a stable random secret for the process lifetime if fallback not provided
    return process.env.JWT_SECRET_FALLBACK || crypto.randomBytes(32).toString('hex');
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

// CSRF Protection for admin routes
const csrfProtection = csrf({ 
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  }
});

app.use('/api/admin', cookieParser(), csrfProtection);

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
        scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", (req, res) => `'nonce-${(res as express.Response).locals.nonce}'`],
        // Allow inline styles for React/Motion
        styleSrc: ["'self'", "'unsafe-inline'", (req, res) => `'nonce-${(res as express.Response).locals.nonce}'`, "https://fonts.googleapis.com"],
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
  backup_codes: string | null;
  failed_attempts: number;
  lockout_until: string | null;
  created_at: string;
}

interface AuthenticatedRequest extends express.Request {
  user?: UserRow;
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

db.exec(`
  CREATE TABLE IF NOT EXISTS pow_nonces (
    id TEXT PRIMARY KEY,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

// Cleanup old PoW nonces every hour
setInterval(() => {
  db.prepare("DELETE FROM pow_nonces WHERE created_at < datetime('now', '-10 minutes')").run();
}, 3600000);

// Rate limiting configurations
const POW_DIFFICULTY = 18; // ~250ms-500ms on modern CPUs. Adjust as needed.

/**
 * PROOF OF WORK (HASHCASH) VALIDATION
 * 
 * This function implements a cryptographic Proof of Work (PoW) verification system
 * designed to protect the application from automated Denial of Service (DoS) and spam attacks.
 * 
 * Security Features:
 * 1. Time-To-Live (TTL): The salt contains a timestamp. Challenges strictly expire after 10 minutes.
 * 2. Replay Protection: A server-side SQLite table (`pow_nonces`) tracks used solutions.
 *    Attempting to reuse a valid `salt:nonce` pair will result in a database constraint error,
 *    instantly rejecting the replay attack.
 * 3. Dynamic Difficulty: The server dictates the number of leading zero bits required in the SHA-256 hash.
 * 
 * @param resource - The specific resource being protected (e.g., 'create_secret').
 * @param salt - The server-provided salt containing the timestamp (format: timestamp_random).
 * @param nonce - The client-computed nonce that solves the challenge.
 * @param difficulty - The required number of leading zero bits in the resulting hash.
 * @returns boolean - True if the PoW is valid, fresh, and unused. False otherwise.
 */
function verifyPoW(resource: string, salt: string, nonce: string, difficulty: number): boolean {
  // 1. Validate Time-To-Live (TTL) to prevent pre-computation attacks
  const parts = salt.split('_');
  if (parts.length !== 2) return false;
  const timestamp = parseInt(parts[0], 10);
  const now = Date.now();
  if (isNaN(timestamp) || now - timestamp > 600000) return false; // Strict 10-minute expiry

  // 2. Enforce Replay Protection via SQLite Unique Constraint
  const powId = `${salt}:${nonce}`;
  try {
    db.prepare("INSERT INTO pow_nonces (id) VALUES (?)").run(powId);
  } catch {
    return false; // Constraint violation: This exact PoW solution has already been used.
  }

  // 3. Cryptographic Hash Verification
  const header = `1:${difficulty}:${resource}:${salt}:${nonce}`;
  const hash = crypto.createHash('sha256').update(header).digest('hex');
  
  const hexToBinary = (hex: string) => {
    return hex.split('').map(h => parseInt(h, 16).toString(2).padStart(4, '0')).join('');
  };
  
  const binaryHash = hexToBinary(hash);
  return binaryHash.startsWith('0'.repeat(difficulty));
}

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { isoBase64URL } from '@simplewebauthn/server/helpers';

const RP_NAME = 'SecureShare Admin';
const RP_ID = process.env.RP_ID || 'localhost';
const ORIGIN = process.env.APP_URL || `http://${RP_ID}:3000`;

/**
 * WEBAUTHN API ROUTES
 */

// Registration Options
app.post("/api/admin/webauthn/register/options", authenticateAdmin, (req, res) => {
  const user = (req as AuthenticatedRequest).user as UserRow;
  
  const userCredentials = db.prepare("SELECT id FROM webauthn_credentials WHERE user_id = ?").all(user.id) as { id: string }[];
  
  const options = generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userID: user.id,
    userName: user.username,
    attestationType: 'none',
    excludeCredentials: userCredentials.map(cred => ({
      id: cred.id,
      type: 'public-key',
    })),
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
  });

  // Store challenge
  const challengeId = uuidv4();
  db.prepare("INSERT INTO webauthn_challenges (id, challenge, user_id, expires_at) VALUES (?, ?, ?, ?)")
    .run(challengeId, options.challenge, user.id, new Date(Date.now() + 5 * 60 * 1000).toISOString());

  res.cookie('webauthn_challenge_id', challengeId, { httpOnly: true, secure: true, sameSite: 'none', maxAge: 5 * 60 * 1000 });
  res.json(options);
});

// Registration Verification
app.post("/api/admin/webauthn/register/verify", authenticateAdmin, async (req, res) => {
  const user = (req as AuthenticatedRequest).user as UserRow;
  const { body } = req;
  const challengeId = req.cookies.webauthn_challenge_id;

  if (!challengeId) return res.status(400).json({ error: "Missing challenge" });

  const challengeRow = db.prepare("SELECT * FROM webauthn_challenges WHERE id = ? AND user_id = ?").get(challengeId, user.id) as { challenge: string, expires_at: string } | undefined;
  
  if (!challengeRow || new Date(challengeRow.expires_at) < new Date()) {
    return res.status(400).json({ error: "Invalid or expired challenge" });
  }

  db.prepare("DELETE FROM webauthn_challenges WHERE id = ?").run(challengeId);
  res.clearCookie('webauthn_challenge_id');

  try {
    const verification = await verifyRegistrationResponse({
      response: body,
      expectedChallenge: challengeRow.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
    });

    if (verification.verified && verification.registrationInfo) {
      const { credentialPublicKey, credentialID, counter } = verification.registrationInfo;

      db.prepare("INSERT INTO webauthn_credentials (id, user_id, public_key, counter, transports) VALUES (?, ?, ?, ?, ?)")
        .run(
          isoBase64URL.fromBuffer(credentialID),
          user.id,
          Buffer.from(credentialPublicKey),
          counter,
          JSON.stringify(body.response.transports || [])
        );

      logAction("WEBAUTHN_REGISTER_SUCCESS", user.id, user.username, req.ip || "unknown");
      res.json({ verified: true });
    } else {
      res.status(400).json({ error: "Verification failed" });
    }
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: "Verification error" });
  }
});

// Get WebAuthn Credentials
app.get("/api/admin/webauthn/credentials", authenticateAdmin, (req, res) => {
  const user = (req as AuthenticatedRequest).user as UserRow;
  const credentials = db.prepare("SELECT id, created_at FROM webauthn_credentials WHERE user_id = ?").all(user.id);
  res.json(credentials);
});

// Delete WebAuthn Credential
app.delete("/api/admin/webauthn/credentials/:id", authenticateAdmin, (req, res) => {
  const user = (req as AuthenticatedRequest).user as UserRow;
  const { id } = req.params;
  db.prepare("DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?").run(id, user.id);
  logAction("WEBAUTHN_DELETE_SUCCESS", user.id, user.username, req.ip || "unknown", `Deleted credential ${id}`);
  res.json({ success: true });
});

// Authentication Options
app.post("/api/admin/webauthn/login/options", async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: "Username required" });

  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username) as UserRow | undefined;
  if (!user) return res.status(404).json({ error: "User not found" });

  const userCredentials = db.prepare("SELECT id FROM webauthn_credentials WHERE user_id = ?").all(user.id) as { id: string }[];

  const options = generateAuthenticationOptions({
    rpID: RP_ID,
    allowCredentials: userCredentials.map(cred => ({
      id: cred.id,
      type: 'public-key',
    })),
    userVerification: 'preferred',
  });

  const challengeId = uuidv4();
  db.prepare("INSERT INTO webauthn_challenges (id, challenge, user_id, expires_at) VALUES (?, ?, ?, ?)")
    .run(challengeId, options.challenge, user.id, new Date(Date.now() + 5 * 60 * 1000).toISOString());

  res.cookie('webauthn_challenge_id', challengeId, { httpOnly: true, secure: true, sameSite: 'none', maxAge: 5 * 60 * 1000 });
  res.json(options);
});

// Authentication Verification
app.post("/api/admin/webauthn/login/verify", async (req, res) => {
  const { body, username } = req.body;
  const challengeId = req.cookies.webauthn_challenge_id;

  if (!challengeId || !username) return res.status(400).json({ error: "Missing challenge or username" });

  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username) as UserRow | undefined;
  if (!user) return res.status(404).json({ error: "User not found" });

  const challengeRow = db.prepare("SELECT * FROM webauthn_challenges WHERE id = ? AND user_id = ?").get(challengeId, user.id) as { challenge: string, expires_at: string } | undefined;
  
  if (!challengeRow || new Date(challengeRow.expires_at) < new Date()) {
    return res.status(400).json({ error: "Invalid or expired challenge" });
  }

  const dbCredential = db.prepare("SELECT * FROM webauthn_credentials WHERE id = ? AND user_id = ?").get(body.id, user.id) as { public_key: Buffer, counter: number, transports: string } | undefined;

  if (!dbCredential) return res.status(400).json({ error: "Credential not found" });

  try {
    const verification = await verifyAuthenticationResponse({
      response: body,
      expectedChallenge: challengeRow.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      authenticator: {
        credentialID: isoBase64URL.toUint8Array(body.id),
        credentialPublicKey: new Uint8Array(dbCredential.public_key),
        counter: dbCredential.counter,
      },
    });

    if (verification.verified) {
      const { newCounter } = verification.authenticationInfo;
      db.prepare("UPDATE webauthn_credentials SET counter = ? WHERE id = ?").run(newCounter, body.id);
      
      // Clear challenge
      db.prepare("DELETE FROM webauthn_challenges WHERE id = ?").run(challengeId);
      res.clearCookie('webauthn_challenge_id');

      // Login success
      const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
      res.cookie('admin_token', token, { 
        httpOnly: true, 
        secure: true,
        sameSite: 'none',
        maxAge: 24 * 60 * 60 * 1000 
      });

      logAction("WEBAUTHN_LOGIN_SUCCESS", user.id, user.username, req.ip || "unknown");
      res.json({ verified: true, username: user.username });
    } else {
      res.status(400).json({ error: "Verification failed" });
    }
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: "Verification error" });
  }
});

/**
 * API ENDPOINTS
 */

// Create a new secret
app.get("/api/health", (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Get PoW Challenge
app.get("/api/pow/challenge", (req, res) => {
  const salt = `${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
  res.json({
    resource: 'secureshare',
    salt,
    difficulty: POW_DIFFICULTY,
    timestamp: Date.now()
  });
});

app.get("/api/admin/csrf-token", (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

app.get("/api/admin/me", authenticateAdmin, (req, res) => {
  const user = (req as AuthenticatedRequest).user as UserRow;
  const webauthnCreds = db.prepare("SELECT COUNT(*) as count FROM webauthn_credentials WHERE user_id = ?").get(user.id) as { count: number };
  
  res.json({
    id: user.id,
    username: user.username,
    isRoot: !!user.is_root,
    mustChangePassword: !!user.must_change_password,
    isTotpEnabled: !!user.is_totp_enabled,
    isWebauthnEnabled: webauthnCreds.count > 0
  });
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

  const trimmedPassword = password.trim();
  const trimmedUsername = username.trim();

  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(trimmedUsername) as UserRow | undefined;
  
  if (!user) {
    logAction("LOGIN_FAILED", null, trimmedUsername, ip, "User not found");
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
    // Legacy SHA-256-based password hashes are no longer accepted to avoid using
    // a fast, insecure hashing scheme on user-supplied passwords. Force a safer
    // migration path (for example, via a password reset flow) instead of
    // recomputing the legacy hash here.
    logAction("LOGIN_FAILED_LEGACY_HASH", user.id, trimmedUsername, ip, "Legacy password hash requires reset");
    return res.status(403).json({ error: "Password reset required for this account." });
  } else {
    isPasswordValid = await bcrypt.compare(trimmedPassword, user.password_hash);
  }

  if (!isPasswordValid) {
    const attempts = user.failed_attempts + 1;
    let lockoutUntil = null;
    if (attempts >= 5) {
      lockoutUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    }
    db.prepare("UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE id = ?").run(attempts, lockoutUntil, user.id);
    logAction("LOGIN_FAILED", user.id, trimmedUsername, ip, `Wrong password. Attempt ${attempts}`);
    return res.status(401).json({ error: "Invalid credentials" });
  }

  // Check TOTP
  if (user.is_totp_enabled) {
    if (!totpToken) {
      return res.status(200).json({ requiresTotp: true });
    }
    const trimmedToken = totpToken.trim();
    let isValid = authenticator.check(trimmedToken, user.totp_secret);
    
    // If not valid TOTP, check backup codes
    if (!isValid && user.backup_codes) {
      const hashedCodes = JSON.parse(user.backup_codes) as string[];
      for (let i = 0; i < hashedCodes.length; i++) {
        const isMatch = await bcrypt.compare(trimmedToken, hashedCodes[i]);
        if (isMatch) {
          isValid = true;
          // Remove used backup code
          hashedCodes.splice(i, 1);
          db.prepare("UPDATE users SET backup_codes = ? WHERE id = ?").run(JSON.stringify(hashedCodes), user.id);
          logAction("BACKUP_CODE_USED", user.id, user.username, ip, `Used backup code. ${hashedCodes.length} remaining.`);
          break;
        }
      }
    }

    if (!isValid) {
      logAction("LOGIN_FAILED_TOTP", user.id, username, ip, "Invalid TOTP or backup code");
      return res.status(401).json({ error: "Invalid TOTP or backup code" });
    }
  }

  // Success
  db.prepare("UPDATE users SET failed_attempts = 0, lockout_until = NULL WHERE id = ?").run(user.id);
  
  const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
  res.cookie('admin_token', token, { 
    httpOnly: true, 
    secure: true, // Required for SameSite=None in iframes
    sameSite: 'none', // Required for cross-origin iframe (AI Studio preview)
    maxAge: 24 * 60 * 60 * 1000 
  });

  logAction("LOGIN_SUCCESS", user.id, username, ip);
  return res.json({ 
    success: true, 
    mustChangePassword: !!user.must_change_password,
    username: user.username
  });
});

app.post("/api/admin/logout", authenticateAdmin, (req, res) => {
  res.clearCookie('admin_token');
  res.json({ success: true });
});

app.post("/api/admin/change-password", authenticateAdmin, async (req, res) => {
  const { newPassword } = req.body;
  const user = (req as AuthenticatedRequest).user as UserRow;

  if (!newPassword || newPassword.length < 12) {
    return res.status(400).json({ error: "Password must be at least 12 characters long" });
  }

  const trimmedPassword = newPassword.trim();

  if (trimmedPassword.length < 12) {
    return res.status(400).json({ error: "Password must be at least 12 characters long" });
  }

  const hash = await bcrypt.hash(trimmedPassword, 12);
  db.prepare("UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?").run(hash, user.id);
  
  logAction("PASSWORD_CHANGED", user.id, user.username, req.ip || "unknown");
  res.json({ success: true });
});

app.get("/api/admin/users", authenticateAdmin, (req, res) => {
  const users = db.prepare("SELECT id, username, is_root, must_change_password, is_totp_enabled, created_at FROM users").all();
  res.json(users);
});

app.post("/api/admin/users", authenticateAdmin, async (req, res) => {
  const { username, password } = req.body;
  const admin = (req as AuthenticatedRequest).user as UserRow;

  if (!username || !password || password.length < 12) {
    return res.status(400).json({ error: "Username and password (min 12 chars) required" });
  }

  try {
    const id = uuidv4();
    const hash = await bcrypt.hash(password, 12);
    db.prepare("INSERT INTO users (id, username, password_hash, must_change_password) VALUES (?, ?, ?, 1)")
      .run(id, username.trim(), hash);
    
    logAction("USER_CREATED", admin.id, admin.username, req.ip || "unknown", `Created user ${username}`);
    res.json({ success: true });
  } catch (err) {
    const error = err as Error;
    if (error.message.includes('UNIQUE')) {
      return res.status(400).json({ error: "Username already exists" });
    }
    res.status(500).json({ error: "Internal server error" });
  }
});

app.delete("/api/admin/users/:id", authenticateAdmin, (req, res) => {
  const admin = (req as AuthenticatedRequest).user as UserRow;
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

app.post("/api/admin/users/:id/reset-2fa", authenticateAdmin, (req, res) => {
  const admin = (req as AuthenticatedRequest).user as UserRow;
  const targetId = req.params.id;

  const target = db.prepare("SELECT * FROM users WHERE id = ?").get(targetId) as UserRow | undefined;
  if (!target) return res.status(404).json({ error: "User not found" });

  db.prepare("UPDATE users SET is_totp_enabled = 0, totp_secret = NULL, backup_codes = NULL WHERE id = ?").run(targetId);
  logAction("USER_2FA_RESET", admin.id, admin.username, req.ip || "unknown", `Reset 2FA for user ${target.username}`);
  res.json({ success: true });
});

app.post("/api/admin/totp/setup", authenticateAdmin, async (req, res) => {
  try {
    const user = (req as AuthenticatedRequest).user as UserRow;
    console.log(`[TOTP] Setting up 2FA for user: ${user.username}`);
    
    if (!authenticator) {
      throw new Error("Authenticator not initialized");
    }

    const secret = authenticator.generateSecret();
    console.log(`[TOTP] Secret generated`);
    
    const otpauth = authenticator.keyuri(user.username.trim(), 'SecureShare', secret);
    console.log(`[TOTP] KeyURI generated: ${otpauth.substring(0, 20)}...`);
    
    const qrCodeUrl = await QRCode.toDataURL(otpauth);
    console.log(`[TOTP] QR Code URL generated`);
    
    db.prepare("UPDATE users SET totp_secret = ?, is_totp_enabled = 0 WHERE id = ?").run(secret, user.id);
    console.log(`[TOTP] Database updated for ${user.username}`);
    
    res.json({ qrCodeUrl, secret });
  } catch (err) {
    console.error("[TOTP] Failed to setup TOTP:", err);
    const message = err instanceof Error ? err.message : "Unknown error";
    res.status(500).json({ error: `Failed to generate QR code: ${message}. Check server logs.` });
  }
});

app.post("/api/admin/totp/verify", authenticateAdmin, async (req, res) => {
  const { token } = req.body;
  const user = (req as AuthenticatedRequest).user as UserRow;

  const dbUser = db.prepare("SELECT totp_secret FROM users WHERE id = ?").get(user.id) as UserRow | undefined;
  if (!dbUser || !dbUser.totp_secret) return res.status(400).json({ error: "TOTP not set up" });

  const trimmedToken = token.trim();
  const isValid = authenticator.check(trimmedToken, dbUser.totp_secret);
  if (isValid) {
    // Generate 10 backup codes
    const codes = Array.from({ length: 10 }, () => crypto.randomBytes(4).toString('hex'));
    const hashedCodes = await Promise.all(codes.map(c => bcrypt.hash(c, 10)));
    
    db.prepare("UPDATE users SET is_totp_enabled = 1, backup_codes = ? WHERE id = ?").run(JSON.stringify(hashedCodes), user.id);
    logAction("TOTP_ENABLED", user.id, user.username, req.ip || "unknown");
    res.json({ success: true, backupCodes: codes });
  } else {
    res.status(400).json({ error: "Invalid token" });
  }
});

app.post("/api/admin/totp/disable", authenticateAdmin, (req, res) => {
  const user = (req as AuthenticatedRequest).user as UserRow;
  db.prepare("UPDATE users SET is_totp_enabled = 0, totp_secret = NULL, backup_codes = NULL WHERE id = ?").run(user.id);
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

app.post("/api/admin/keys", authenticateAdmin, async (req, res) => {
  const { name } = req.body;
  const admin = (req as AuthenticatedRequest).user as UserRow;
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

app.delete("/api/admin/keys/:id", authenticateAdmin, (req, res) => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const admin = (req as any).user as UserRow;
  db.prepare("DELETE FROM api_keys WHERE id = ?").run(req.params.id);
  logAction("API_KEY_DELETED", admin.id, admin.username, req.ip || "unknown", `Deleted key ${req.params.id}`);
  res.json({ success: true });
});

app.post("/api/secrets", createLimiter, verifyApiKey, (req, res) => {
  const { powNonce, powSalt } = req.body;
  const apiKey = req.headers['x-api-key'];

  // Verify Proof of Work
  // Exempt requests authenticated with a valid API Key
  const isApiKeyAuthenticated = !!apiKey; // verifyApiKey middleware ensures if apiKey is present, it's valid or next() is not called with error

  if (!isApiKeyAuthenticated && (process.env.NODE_ENV === 'production' || req.headers['x-enforce-pow'])) {
    if (!powNonce || !powSalt || !verifyPoW('secureshare', powSalt, powNonce, POW_DIFFICULTY)) {
      return res.status(402).json({ 
        error: "Proof of Work required. Solve challenge first.",
        challenge_url: "/api/pow/challenge"
      });
    }
  }

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
  console.log(`Starting server on port ${PORT}...`);
  
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server is listening on http://0.0.0.0:${PORT}`);
  });

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

  // Global error handler
  // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars
  app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    console.error('Unhandled error:', err);
    res.status(500).send('Internal Server Error');
  });
};

// Start server
startServer().catch(console.error);
