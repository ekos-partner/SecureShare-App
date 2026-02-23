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
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cors from "cors";
import { z } from "zod";
import crypto from 'node:crypto';
import ejs from 'ejs';

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
  } catch {
    // Fallback to /tmp for environments with read-only filesystems (like some Cloud Run setups)
    console.error(`Failed to open database at ${dbPath}, trying /tmp/secrets.db`);
    return new Database("/tmp/secrets.db");
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
  expirationHours: z.union([z.string(), z.number()]).transform(v => Number(v)),
  viewLimit: z.union([z.string(), z.number()]).transform(v => Number(v)),
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

async function startServer() {
  const app = express();
  const PORT = 3000;

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
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        scriptSrc: ["'self'", (req, res) => `'nonce-${(res as any).locals.nonce}'`],
        // Restored 'unsafe-inline' for styles as many React/Motion components require it
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        styleSrc: ["'self'", "'unsafe-inline'", (req, res) => `'nonce-${(res as any).locals.nonce}'`, "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:", "https://picsum.photos", "blob:"],
        // Tightened connectSrc to address "CSP: Wildcard Directive"
        connectSrc: ["'self'"],
        // frameAncestors must allow Google domains for the AI Studio preview to function
        frameAncestors: ["'self'", "https://*.google.com", "https://*.run.app", "https://*.aistudio.google.com"],
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

  // Restricted CORS: Only allow specific APP_URL if defined, otherwise same-origin only
  // This fixes the "Cross-Domain Misconfiguration"
  const allowedOrigin = process.env.APP_URL || false; 
  if (allowedOrigin) {
    app.use(cors({
      origin: allowedOrigin,
      methods: ["GET", "POST"],
      credentials: true
    }));
  }
  app.use(express.json({ limit: '1.1mb' }));

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
  app.post("/api/secrets", createLimiter, (req, res) => {
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
  const isProd = process.env.NODE_ENV === "production";
  
  if (!isProd) {
    // Development mode: Use Vite middleware and EJS for nonce injection
    const { createServer: createViteServer } = await import("vite");
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
    app.get('*', async (req, res, next) => {
      try {
        // Sanitize URL to prevent XSS warnings from Snyk (CWE-79)
        // We only need the path for Vite's transformIndexHtml
        const url = req.path; 
        const template = await vite.transformIndexHtml(url, fs.readFileSync(path.resolve(process.cwd(), 'index.html'), 'utf-8'));
        // Use simple string replacement instead of ejs.render to avoid "dynamically formatted template" security warnings
        const renderedHtml = template.replace(/<%= nonce %>/g, res.locals.nonce);
        res.status(200).set({ 'Content-Type': 'text/html' }).end(renderedHtml);
      } catch (e) {
        if (isProd) {
          console.error(e);
        } else {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          vite.ssrFixStacktrace(e as any);
        }
        next(e);
      }
    });
  } else {
    // Production mode: Serve pre-built static files from /dist
    const distPath = path.resolve(process.cwd(), "dist");
    if (fs.existsSync(distPath)) {
      app.engine('html', ejs.renderFile);
      app.set('view engine', 'html');
      app.set('views', distPath);

      app.use(express.static(distPath));
      app.get("*", (req, res) => {
        res.render(path.resolve(distPath, "index.html"), { nonce: res.locals.nonce });
      });
    } else {
      console.warn("Production build 'dist' folder not found. Static files will not be served.");
    }
  }

  // Security.txt implementation (RFC 9116)
  app.get(["/.well-known/security.txt", "/security.txt"], (req, res) => {
    const securityTxt = `Contact: mailto:security@${req.hostname}
Expires: ${new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()}
Preferred-Languages: en, pl
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
}

startServer();
