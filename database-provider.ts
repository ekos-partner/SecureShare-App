import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import Database from "better-sqlite3";
import { initializeApp } from "firebase/app";
import {
  getFirestore,
  doc,
  getDoc,
  setDoc,
  deleteDoc,
  updateDoc,
  collection,
  getDocs,
  query,
  where,
  runTransaction
} from "firebase/firestore";

/**
 * DATABASE SECRET ROW SCHEMA TYPE
 * This matches exactly how secrets are returned.
 */
export interface SecretRow {
  id: string;
  encrypted_data: string;
  password_hash: string | null;
  salt: string | null;
  expires_at: string;
  view_limit: number;
  view_count: number;
  failed_attempts: number;
  kdf_config: string | null;
  created_at: string;
}

/**
 * DATABASE PROVIDER INTERFACE
 * An abstract interface that handles all storage operations for SecureShare.
 * This permits seamless switching between local SQLite (for self-hosting)
 * and Cloud Firestore (for serverless environments like GCP Cloud Run).
 */
export interface IDatabaseProvider {
  initialize(): Promise<void>;
  createSecret(secret: {
    id: string;
    encryptedData: string;
    passwordHash: string | null;
    salt: string | null;
    expiresAt: string;
    viewLimit: number;
    kdfConfig: string | null;
  }): Promise<void>;
  getSecret(id: string): Promise<SecretRow | null>;
  deleteSecret(id: string): Promise<void>;
  incrementFailedAttempts(id: string, newAttempts: number): Promise<void>;
  incrementViewCount(id: string, newCount: number): Promise<void>;
  deleteExpiredSecrets(now: string): Promise<number>;
  registerPoWNonce(powId: string): Promise<boolean>;
  logEvent(event: string, details?: string): Promise<void>;
  cleanupPoWNonces(): Promise<void>;
}

/**
 * SQLITE PROVIDER IMPLEMENTATION
 * Default provider for self-hosted instances. Uses local better-sqlite3 with
 * automatic local mirroring if running inside a container with GCS FUSE.
 */
export class SqliteProvider implements IDatabaseProvider {
  private db!: Database.Database;
  private isGcsActive = false;
  private gcsDbPath = "";
  private localDbPath = "";

  private syncDbToStorage(): void {
    if (!this.isGcsActive || !this.localDbPath || !this.gcsDbPath) return;
    try {
      fs.copyFileSync(this.localDbPath, this.gcsDbPath);
      console.log(`[SQLITE] Synchronized local database to GCS FUSE: ${this.gcsDbPath}`);
    } catch (syncErr) {
      console.error(`[SQLITE ERROR] Failed to synchronize SQLite to GCE/GCS FUSE:`, syncErr);
    }
  }

  public async initialize(): Promise<void> {
    const dbPath = process.env.DB_PATH || path.join(process.cwd(), "data", "secrets.db");
    const isGcs = dbPath.startsWith("/data") || dbPath.includes("secureshare-storage-db");

    if (isGcs) {
      const tmpDbPath = path.join(os.tmpdir(), "secureshare-secrets-local.db");
      this.localDbPath = tmpDbPath;
      this.gcsDbPath = dbPath;
      this.isGcsActive = true;

      console.log(`[SQLITE] GCS FUSE storage detected. Mirroring to local workspace to prevent locking issues.`);

      const remoteDir = path.dirname(this.gcsDbPath);
      if (!fs.existsSync(remoteDir)) {
        try {
          fs.mkdirSync(remoteDir, { recursive: true });
        } catch (err) {
          console.warn(`[SQLITE] Could not create directory ${remoteDir}:`, err);
        }
      }

      if (fs.existsSync(this.gcsDbPath)) {
        try {
          console.log(`[SQLITE] Downloading remote FUSE DB to local cache...`);
          fs.copyFileSync(this.gcsDbPath, this.localDbPath);
        } catch (copyErr) {
          console.error(`[SQLITE] Cloud download failed. Starting clear internal DB:`, copyErr);
        }
      }
      this.db = new Database(this.localDbPath);
    } else {
      const dbDir = path.dirname(dbPath);
      if (!fs.existsSync(dbDir)) {
        fs.mkdirSync(dbDir, { recursive: true });
      }
      try {
        this.db = new Database(dbPath);
      } catch {
        const tmpFallback = path.join(os.tmpdir(), "secureshare-secrets.db");
        console.warn(`[SQLITE WARNING] Using temp fallback path: ${tmpFallback}`);
        this.db = new Database(tmpFallback);
      }
    }

    try {
      this.db.pragma("busy_timeout = 10000");
      this.db.pragma("journal_mode = DELETE");
    } catch (pragmaError) {
      console.warn("Failed to set SQLite pragmas:", pragmaError);
    }

    // Instantiating DB Schema mapping
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS secrets (
        id TEXT PRIMARY KEY,
        encrypted_data TEXT NOT NULL,
        password_hash TEXT,
        salt TEXT,
        expires_at DATETIME NOT NULL,
        view_limit INTEGER DEFAULT 1,
        view_count INTEGER DEFAULT 0,
        failed_attempts INTEGER DEFAULT 0,
        kdf_config TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS pow_nonces (
        id TEXT PRIMARY KEY,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        event TEXT NOT NULL,
        details TEXT
      )
    `);

    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_secrets_expires_at ON secrets (expires_at)`);

    // Schema Migrations
    const tables = ["salt TEXT", "failed_attempts INTEGER DEFAULT 0", "kdf_config TEXT"];
    for (const spec of tables) {
      try {
        this.db.exec(`ALTER TABLE secrets ADD COLUMN ${spec}`);
      } catch {
        // Already exists
      }
    }

    if (this.isGcsActive) {
      this.syncDbToStorage();
    }
  }

  public async createSecret(secret: {
    id: string;
    encryptedData: string;
    passwordHash: string | null;
    salt: string | null;
    expiresAt: string;
    viewLimit: number;
    kdfConfig: string | null;
  }): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT INTO secrets (id, encrypted_data, password_hash, salt, expires_at, view_limit, kdf_config)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      secret.id,
      secret.encryptedData,
      secret.passwordHash,
      secret.salt,
      secret.expiresAt,
      secret.viewLimit,
      secret.kdfConfig
    );
    this.syncDbToStorage();
  }

  public async getSecret(id: string): Promise<SecretRow | null> {
    try {
      const row = this.db.prepare("SELECT * FROM secrets WHERE id = ?").get(id) as SecretRow | undefined;
      return row || null;
    } catch (err) {
      console.error("[SQLITE ERROR] Error reading secret:", err);
      return null;
    }
  }

  public async deleteSecret(id: string): Promise<void> {
    this.db.prepare("DELETE FROM secrets WHERE id = ?").run(id);
    this.syncDbToStorage();
  }

  public async incrementFailedAttempts(id: string, newAttempts: number): Promise<void> {
    this.db.prepare("UPDATE secrets SET failed_attempts = ? WHERE id = ?").run(newAttempts, id);
    this.syncDbToStorage();
  }

  public async incrementViewCount(id: string, newCount: number): Promise<void> {
    this.db.prepare("UPDATE secrets SET view_count = ? WHERE id = ?").run(newCount, id);
    this.syncDbToStorage();
  }

  public async deleteExpiredSecrets(now: string): Promise<number> {
    const result = this.db.prepare("DELETE FROM secrets WHERE expires_at < ?").run(now);
    if (result.changes > 0) {
      this.syncDbToStorage();
    }
    return result.changes;
  }

  public async registerPoWNonce(powId: string): Promise<boolean> {
    try {
      this.db.prepare("INSERT INTO pow_nonces (id) VALUES (?)").run(powId);
      return true;
    } catch {
      return false; // Unique key constraint failed: replay detected!
    }
  }

  public async logEvent(event: string, details: string = ""): Promise<void> {
    try {
      this.db.prepare("INSERT INTO logs (event, details) VALUES (?, ?)").run(event, details);
      // Prune logs
      this.db.prepare(`
        DELETE FROM logs WHERE id NOT IN (
          SELECT id FROM logs ORDER BY timestamp DESC LIMIT 1000
        )
      `).run();
    } catch (err) {
      console.error("[SQLITE LOG ERROR] Could not log event:", err);
    }
  }

  public async cleanupPoWNonces(): Promise<void> {
    this.db.prepare("DELETE FROM pow_nonces WHERE created_at < datetime('now', '-10 minutes')").run();
  }
}

/**
 * FIRESTORE DB PROVIDER
 * Robust, highly persistent serverless DB provider. Keeps secrets across container restarts,
 * dynamic scaling to 0, or code publishes. Extremely fast and transactional.
 */
export class FirestoreProvider implements IDatabaseProvider {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private firestoreDb: any;

  public async initialize(): Promise<void> {
    console.log("[FIRESTORE] Cloud Firestore selected. Reading config from firebase-applet-config.json...");
    try {
      const configPath = path.join(process.cwd(), "firebase-applet-config.json");
      const configContent = fs.readFileSync(configPath, "utf-8");
      const firebaseConfig = JSON.parse(configContent);
      
      const app = initializeApp(firebaseConfig);
      this.firestoreDb = getFirestore(app, firebaseConfig.firestoreDatabaseId);
      console.log(`[FIRESTORE] Connected successfully to enterprise Cloud database instance: ${firebaseConfig.firestoreDatabaseId}`);
    } catch (err) {
      console.error("[FIRESTORE CRITICAL ERROR] Failed to connect server side to Firestore database:", err);
      throw err;
    }
  }

  public async createSecret(secret: {
    id: string;
    encryptedData: string;
    passwordHash: string | null;
    salt: string | null;
    expiresAt: string;
    viewLimit: number;
    kdfConfig: string | null;
  }): Promise<void> {
    const docRef = doc(this.firestoreDb, "secrets", secret.id);
    await setDoc(docRef, {
      id: secret.id,
      encrypted_data: secret.encryptedData,
      password_hash: secret.passwordHash || null,
      salt: secret.salt || null,
      expires_at: secret.expiresAt,
      view_limit: secret.viewLimit,
      view_count: 0,
      failed_attempts: 0,
      kdf_config: secret.kdfConfig || null,
      created_at: new Date().toISOString()
    });
  }

  public async getSecret(id: string): Promise<SecretRow | null> {
    try {
      const docRef = doc(this.firestoreDb, "secrets", id);
      const snap = await getDoc(docRef);
      if (!snap.exists()) return null;
      
      const data = snap.data();
      // Map Firestore document data back to SQLite model style (snake_case)
      // to avoid refactoring model parameters across server.ts routes
      return {
        id: data.id,
        encrypted_data: data.encrypted_data,
        password_hash: data.password_hash ?? null,
        salt: data.salt ?? null,
        expires_at: data.expires_at,
        view_limit: data.view_limit,
        view_count: data.view_count || 0,
        failed_attempts: data.failed_attempts || 0,
        kdf_config: data.kdf_config ?? null,
        created_at: data.created_at
      } as SecretRow;
    } catch (err) {
      console.error("[FIRESTORE ERROR] Reading secret failed:", err);
      return null;
    }
  }

  public async deleteSecret(id: string): Promise<void> {
    const docRef = doc(this.firestoreDb, "secrets", id);
    await deleteDoc(docRef);
  }

  public async incrementFailedAttempts(id: string, newAttempts: number): Promise<void> {
    const docRef = doc(this.firestoreDb, "secrets", id);
    await updateDoc(docRef, { failed_attempts: newAttempts });
  }

  public async incrementViewCount(id: string, newCount: number): Promise<void> {
    const docRef = doc(this.firestoreDb, "secrets", id);
    await updateDoc(docRef, { view_count: newCount });
  }

  public async deleteExpiredSecrets(now: string): Promise<number> {
    let deletedCount = 0;
    try {
      const secretsColl = collection(this.firestoreDb, "secrets");
      const q = query(secretsColl, where("expires_at", "<", now));
      const querySnap = await getDocs(q);
      
      for (const d of querySnap.docs) {
        await deleteDoc(doc(this.firestoreDb, "secrets", d.id));
        deletedCount++;
      }
    } catch (err) {
      console.error("[FIRESTORE ERROR] Error cleaning expired records:", err);
    }
    return deletedCount;
  }

  public async registerPoWNonce(powId: string): Promise<boolean> {
    const nonceRef = doc(this.firestoreDb, "pow_nonces", powId);
    try {
      const result = await runTransaction(this.firestoreDb, async (transaction) => {
        const docSnap = await transaction.get(nonceRef);
        if (docSnap.exists()) {
          return false; // Already created, replay detected!
        }
        transaction.set(nonceRef, { created_at: new Date().toISOString() });
        return true; // Successfully registered nonce
      });
      return result;
    } catch (txErr) {
      console.error("[FIRESTORE TRANSACTION ERROR] Proof-of-work registration transaction failed:", txErr);
      return false;
    }
  }

  public async logEvent(event: string, details: string = ""): Promise<void> {
    // Cloud environments natively aggregate stdout logs cleanly and securely
    // to Google Cloud Logging. To avoid excessive write charges, we log directly to console
    // where they can be dynamically searched and audited on Cloud console.
    console.log(`[EVENT LOG] Event: ${event} | Details: ${details}`);
    
    // As a backup, we also log to Firestore to preserve a simple visual state if desired
    try {
      const logRef = doc(collection(this.firestoreDb, "logs"));
      await setDoc(logRef, {
        id: logRef.id,
        timestamp: new Date().toISOString(),
        event,
        details
      });
    } catch {
      // safe fallback
    }
  }

  public async cleanupPoWNonces(): Promise<void> {
    // Cleanup old nonces from firestore to prevent bloat
    try {
      const now = Date.now();
      const tenMinutesAgo = new Date(now - 10 * 60 * 1000).toISOString();
      const coll = collection(this.firestoreDb, "pow_nonces");
      const q = query(coll, where("created_at", "<", tenMinutesAgo));
      const snap = await getDocs(q);
      for (const d of snap.docs) {
        await deleteDoc(doc(this.firestoreDb, "pow_nonces", d.id));
      }
    } catch (err) {
      console.warn("[FIRESTORE CLEANUP ERROR] PoW Nonce cleanup warning:", err);
    }
  }
}

/**
 * DATABASE FACTORY / RESOLVER
 * Auto-resolves whether to leverage Cloud Firestore or SQLite.
 * Detects presence of firebase-applet-config.json configuration file.
 */
export function getDatabaseProvider(): IDatabaseProvider {
  const configPath = path.join(process.cwd(), "firebase-applet-config.json");
  const hasFirebaseConfig = fs.existsSync(configPath);
  const preferredProvider = process.env.DATABASE_PROVIDER;

  if (preferredProvider === "sqlite") {
    console.log("[DATABASE FACTORY] SQLite provider explicitly requested.");
    return new SqliteProvider();
  }

  if (preferredProvider === "firestore" || (hasFirebaseConfig && preferredProvider !== "sqlite")) {
    return new FirestoreProvider();
  }

  console.log("[DATABASE FACTORY] Defaulting to SQLite database provider (local filesystem).");
  return new SqliteProvider();
}

/**
 * EXPORTED INITIALIZED INSTANCE
 */
export const db: IDatabaseProvider = getDatabaseProvider();
