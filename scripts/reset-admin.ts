import Database from "better-sqlite3";
import crypto from "node:crypto";
import path from "node:path";
import fs from "node:fs";

const dbPath = process.env.DB_PATH || path.join(process.cwd(), "secrets.db");

if (!fs.existsSync(dbPath)) {
  console.error(`Database not found at ${dbPath}`);
  process.exit(1);
}

const db = new Database(dbPath);

const username = process.argv[2];
const newPassword = process.argv[3];

if (!username || !newPassword) {
  console.log("Usage: npm run reset-admin <username> <new-password>");
  process.exit(1);
}

const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username) as { id: string, username: string, password_hash: string } | undefined;

if (!user) {
  console.error(`User '${username}' not found.`);
  process.exit(1);
}

const hash = crypto.createHash('sha256').update(newPassword).digest('hex');
db.prepare("UPDATE users SET password_hash = ?, must_change_password = 0, failed_attempts = 0, lockout_until = NULL WHERE id = ?")
  .run(hash, user.id);

console.log(`Successfully reset password for user '${username}'.`);
console.log("Any active lockouts have been cleared.");
process.exit(0);
