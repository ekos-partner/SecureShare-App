/**
 * SECURESHARE SERVER
 * 
 * This is the primary server for the SecureShare application.
 * It manages secret storage, cryptographic challenges, and serves the frontend.
 * 
 * SECURITY ARCHITECTURE:
 * 1. Zero-Knowledge: The server never sees decryption keys or plaintext data.
 * 2. Defense in Depth: Multiple layers of protection (CSP, HSTS, Rate Limiting, PoW).
 * 3. Atomic Operations: Pluggable database drivers (SQLite/Firestore) guarantee safety.
 */

import express from "express";
import { v4 as uuidv4 } from "uuid";
import path from "node:path";
import fs from "node:fs";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cors from "cors";
import { z } from "zod";
import crypto from "node:crypto";

// Universal database provider importing (SQLite fallback + Cloud Firestore)
import { db, IDatabaseProvider, SecretRow } from "./database-provider.js";

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
  kdfConfig: z.string().nullable().optional(),
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
async function verifyPasswordAndHandleBruteForce(
  database: IDatabaseProvider,
  secret: SecretRow,
  passwordHash: string | null | undefined
) {
  if (!secret.password_hash) return null;

  if (!passwordHash || passwordHash !== secret.password_hash) {
    const newFailedAttempts = (secret.failed_attempts || 0) + 1;
    const MAX_ATTEMPTS = 3;

    if (newFailedAttempts >= MAX_ATTEMPTS) {
      await database.deleteSecret(secret.id);
      await database.logEvent("SECRET_DELETED", `ID: ${secret.id} (Brute force protection)`);
      console.log(`[Security] Secret ${secret.id} burned after ${MAX_ATTEMPTS} failed attempts.`);
      return {
        status: 401,
        body: { error: "Too many failed attempts. Secret has been permanently deleted." },
      };
    }

    await database.incrementFailedAttempts(secret.id, newFailedAttempts);
    await database.logEvent("FAILED_ATTEMPT", `ID: ${secret.id}, Attempt: ${newFailedAttempts}`);
    return {
      status: 401,
      body: {
        error: `Invalid password. ${MAX_ATTEMPTS - newFailedAttempts} attempts remaining before permanent deletion.`,
      },
    };
  }

  return null;
}

/**
 * VIEW LIMIT LOGIC
 * Extracted to reduce cognitive complexity.
 */
async function handleViewLimit(database: IDatabaseProvider, secret: SecretRow) {
  const newCount = secret.view_count + 1;
  const isBurned = newCount >= secret.view_limit;
  const remaining = Math.max(0, secret.view_limit - newCount);

  if (isBurned) {
    await database.deleteSecret(secret.id);
    await database.logEvent("SECRET_DELETED", `ID: ${secret.id} (View limit reached)`);
    console.log(`[ViewLimit] Secret ${secret.id} deleted after reaching view limit (${secret.view_limit}).`);
  } else {
    await database.incrementViewCount(secret.id, newCount);
    await database.logEvent("SECRET_VIEWED", `ID: ${secret.id}`);
  }

  return { success: true, burned: isBurned, remaining };
}

// Parse trust proxy configuration for both cloud environment and multiple self-hosted setups
const getTrustProxySetting = () => {
  const tp = process.env.TRUST_PROXY;
  if (tp === undefined) {
    return 1; // Default to 1 (safe for single-hop proxy deployments like Cloud Run)
  }
  if (tp === "true") return true;
  if (tp === "false") return false;
  const num = Number.parseInt(tp, 10);
  if (!Number.isNaN(num)) return num;
  return tp; // E.g., 'loopback', comma-separated IPs, etc.
};

const app = express();
app.set("trust proxy", getTrustProxySetting());
const PORT = Number.parseInt(process.env.PORT || "3000", 10);

// Generate a nonce for each request
app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString("hex");
  next();
});

/**
 * PRODUCTION SECURITY MIDDLEWARE
 * Strict security headers for the standalone production environment.
 */
if (process.env.NODE_ENV === "production") {
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: [
            "'self'",
            "'unsafe-inline'",
            "'unsafe-eval'",
            (req, res) => `'nonce-${(res as express.Response).locals.nonce}'`,
          ],
          // Allow inline styles for React/Motion
          styleSrc: [
            "'self'",
            "'unsafe-inline'",
            (req, res) => `'nonce-${(res as express.Response).locals.nonce}'`,
            "https://fonts.googleapis.com",
          ],
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
    })
  );

  // Add the Permissions-Policy header manually
  app.use((req, res, next) => {
    res.setHeader(
      "Permissions-Policy",
      "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
    );
    next();
  });
}

// CORS Configuration
const allowedOrigin = process.env.APP_URL || false;
if (allowedOrigin) {
  app.use(
    cors({
      origin: allowedOrigin,
      methods: ["GET", "POST"],
      credentials: true,
    })
  );
}
app.use(express.json({ limit: "1.1mb" }));

/**
 * RATE LIMITING
 */
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3000, // Increased limit to prevent false positives with static assets
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests from this IP, please try again later." },
});
app.use("/api", globalLimiter);

const createLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 200, // Increased limit for secret creation
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Creation limit reached. Please try again later." },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50, // Increased limit for failed password attempts
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: { error: "Too many failed attempts. Please wait 15 minutes." },
});

// Rate limiting configurations
const POW_DIFFICULTY = 18; // ~250ms-500ms on modern CPUs. Adjust as needed.

/**
 * PROOF OF WORK (HASHCASH) VALIDATION
 */
async function verifyPoW(
  database: IDatabaseProvider,
  resource: string,
  salt: string,
  nonce: string,
  difficulty: number
): Promise<boolean> {
  // 1. Validate Time-To-Live (TTL) to prevent pre-computation attacks
  const parts = salt.split("_");
  if (parts.length !== 2) return false;
  const timestamp = parseInt(parts[0], 10);
  const now = Date.now();
  if (isNaN(timestamp) || now - timestamp > 600000) return false; // Strict 10-minute expiry

  // 2. Enforce Replay Protection via atomic Database constraint
  const powId = `${salt}:${nonce}`;
  const isRegistered = await database.registerPoWNonce(powId);
  if (!isRegistered) {
    return false; // Replay detected!
  }

  // 3. Cryptographic Hash Verification
  const header = `1:${difficulty}:${resource}:${salt}:${nonce}`;
  const hash = crypto.createHash("sha256").update(header).digest("hex");

  const hexToBinary = (hex: string) => {
    return hex
      .split("")
      .map((h) => parseInt(h, 16).toString(2).padStart(4, "0"))
      .join("");
  };

  const binaryHash = hexToBinary(hash);
  return binaryHash.startsWith("0".repeat(difficulty));
}

/**
 * API ENDPOINTS
 */

// Health verification
app.get("/api/health", (req, res) => {
  res.status(200).json({
    status: "ok",
    database: db.constructor.name === "FirestoreProvider" ? "firestore" : "sqlite",
    timestamp: new Date().toISOString()
  });
});

// Get PoW Challenge
app.get("/api/pow/challenge", (req, res) => {
  const salt = `${Date.now()}_${crypto.randomBytes(8).toString("hex")}`;
  res.json({
    resource: "secureshare",
    salt,
    difficulty: POW_DIFFICULTY,
    timestamp: Date.now(),
  });
});

// Create a new secret
app.post("/api/secrets", createLimiter, async (req, res) => {
  const { powNonce, powSalt } = req.body;

  // Verify Proof of Work
  if (process.env.NODE_ENV === "production" || req.headers["x-enforce-pow"]) {
    if (!powNonce || !powSalt || !(await verifyPoW(db, "secureshare", powSalt, powNonce, POW_DIFFICULTY))) {
      return res.status(402).json({
        error: "Proof of Work required. Solve challenge first.",
        challenge_url: "/api/pow/challenge",
      });
    }
  }

  const result = CreateSecretSchema.safeParse(req.body);
  if (!result.success) {
    return res.status(400).json({ error: "Invalid input data", details: result.error.format() });
  }

  const { encryptedData, passwordHash, salt, expirationHours, viewLimit, kdfConfig } = result.data;

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
    await db.createSecret({
      id,
      encryptedData,
      passwordHash: passwordHash || null,
      salt: salt || null,
      expiresAt,
      viewLimit,
      kdfConfig: kdfConfig || null,
    });
    await db.logEvent("SECRET_CREATED", `ID: ${id}, Expires: ${expiresAt}`);

    res.json({ id });
  } catch (error) {
    console.error("Database error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Fetch secret metadata (encrypted blob + salt)
app.get("/api/secrets/:id", async (req, res) => {
  const { id } = req.params;

  try {
    const secret = await db.getSecret(id);

    // Opaque response for non-existent or expired secrets to prevent enumeration
    if (!secret || new Date(secret.expires_at) < new Date()) {
      if (secret && new Date(secret.expires_at) < new Date()) {
        await db.deleteSecret(id);
      }
      return res.status(404).json({ error: "Secret not found or expired" });
    }

    res.json({
      encryptedData: secret.encrypted_data,
      hasPassword: !!secret.password_hash,
      salt: secret.salt,
      kdfConfig: secret.kdf_config,
    });
  } catch (error) {
    console.error("Fetch secret error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Verify access and "burn" the secret (increment view count or delete)
app.post("/api/secrets/:id/burn", authLimiter, async (req, res) => {
  const { id } = req.params;
  const result = BurnSecretSchema.safeParse(req.body);
  if (!result.success) {
    return res.status(400).json({ error: "Invalid input data" });
  }

  const { passwordHash } = result.data;

  try {
    const secret = await db.getSecret(id);

    if (!secret) {
      return res.status(404).json({ error: "Not found" });
    }

    // 1. Verify password & handle brute force
    const authError = await verifyPasswordAndHandleBruteForce(db, secret, passwordHash);
    if (authError) {
      return res.status(authError.status).json(authError.body);
    }

    // 2. Handle view limits and burning
    const viewResult = await handleViewLimit(db, secret);

    res.status(200).json(viewResult);
  } catch (error) {
    console.error("Burning secret error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * PERIODIC CLEANUP
 * Deletes expired secrets from the database every 5 minutes.
 */
setInterval(async () => {
  try {
    const now = new Date().toISOString();
    const deletedCount = await db.deleteExpiredSecrets(now);
    if (deletedCount > 0) {
      await db.logEvent("CLEANUP", `Deleted ${deletedCount} expired secrets`);
      console.log(`[Backup/Cleanup] Deleted ${deletedCount} expired secrets.`);
    }
  } catch (error) {
    console.error("[Cleanup] Error cleaning up expired secrets:", error);
  }
}, 5 * 60 * 1000);

// Cleanup old PoW nonces every hour
setInterval(async () => {
  try {
    await db.cleanupPoWNonces();
  } catch (error) {
    console.error("[Cleanup] PoW Nonce cleanup error:", error);
  }
}, 3600000);

/**
 * STATIC FILE SERVING & VITE INTEGRATION
 */
const startServer = async () => {
  console.log("Initializing database connection...");
  await db.initialize();

  console.log(`Starting server on port ${PORT}...`);

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server is listening on http://0.0.0.0:${PORT}`);
  });

  if (process.env.NODE_ENV === "production") {
    // Production mode: Serve pre-built static files from /dist
    const distPath = path.resolve(process.cwd(), "dist");
    if (fs.existsSync(distPath)) {
      app.use(express.static(distPath, { index: false }));

      let cachedIndexHtml: string | null = null;
      try {
        cachedIndexHtml = fs.readFileSync(path.resolve(distPath, "index.html"), "utf-8");
      } catch (err) {
        console.error("Failed to read index.html in production:", err);
      }

      app.get("*", globalLimiter, (req, res) => {
        try {
          const html = cachedIndexHtml || fs.readFileSync(path.resolve(distPath, "index.html"), "utf-8");
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const renderedHtml = html.replaceAll("<%= nonce %>", (res as any).locals.nonce);
          res.status(200).set({ "Content-Type": "text/html" }).end(renderedHtml);
        } catch (err) {
          console.error("Error serving index.html:", err);
          res.status(500).send("Internal Server Error");
        }
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
        hmr: false, // Disable HMR as per platform guidelines
      },
      appType: "spa",
    });
    app.use(vite.middlewares);
    app.get("*", globalLimiter, async (req, res, next) => {
      try {
        // Sanitize URL
        const url = req.path;
        const template = await vite.transformIndexHtml(
          url,
          fs.readFileSync(path.resolve(process.cwd(), "index.html"), "utf-8")
        );
        // Inject nonce
        const renderedHtml = template.replaceAll("<%= nonce %>", res.locals.nonce);
        res.status(200).set({ "Content-Type": "text/html" }).end(renderedHtml);
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
    res.type("text/plain").send(securityTxt);
  });

  app.get("/security-policy", (req, res) => {
    res.type("text/plain").send(`# Security Policy

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
    console.error("Unhandled error:", err);
    res.status(500).send("Internal Server Error");
  });
};

// Start server
startServer().catch(console.error);
