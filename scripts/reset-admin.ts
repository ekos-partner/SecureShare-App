import Database from "better-sqlite3";
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const bcrypt = require("bcrypt");
import path from "node:path";
import fs from "node:fs";
import dotenv from "dotenv";

dotenv.config();

const dbPath = process.env.DB_PATH || path.join(process.cwd(), "data", "secrets.db");

if (!fs.existsSync(dbPath)) {
  console.error(`Database not found at ${dbPath}`);
  process.exit(1);
}

const db = new Database(dbPath);

async function run() {
  const username = process.argv[2];
  const newPassword = process.argv[3];

  if (!username || !newPassword || newPassword.length < 12) {
    console.log("Usage: npm run reset-admin <username> <new-password>");
    console.log("Error: Password must be at least 12 characters long.");
    process.exit(1);
  }

  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username) as { id: string, username: string } | undefined;

  if (!user) {
    console.error(`User '${username}' not found.`);
    process.exit(1);
  }

  const hash = await bcrypt.hash(newPassword, 12);
  db.prepare("UPDATE users SET password_hash = ?, must_change_password = 0, failed_attempts = 0, lockout_until = NULL, totp_secret = NULL, is_totp_enabled = 0, backup_codes = NULL WHERE id = ?")
    .run(hash, user.id);

  console.log(`Successfully reset password and cleared 2FA/Backup codes for user '${username}'.`);
  console.log("Any active lockouts have been cleared.");
  process.exit(0);
}

run().catch(console.error);
