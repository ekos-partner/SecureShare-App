/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import bcrypt from 'bcrypt';
import Database from 'better-sqlite3';
import dotenv from 'dotenv';
import path from 'path';

// Load environment variables from .env file
dotenv.config({ path: path.resolve(process.cwd(), '.env') });

const DB_PATH = process.env.DB_PATH || path.resolve(process.cwd(), 'data', 'secrets.db');

async function resetAdminPassword() {
  const newPassword = process.argv[2];

  if (!newPassword) {
    console.error('ERROR: Please provide a new password as an argument.');
    console.log('Usage: npm run reset:admin-password -- "your-new-strong-password"');
    process.exit(1);
  }

  if (newPassword.length < 8) {
    console.error('ERROR: The new password must be at least 8 characters long.');
    process.exit(1);
  }

  try {
    const db = new Database(DB_PATH);

    const admin = db.prepare("SELECT id FROM users WHERE username = 'admin'").get();
    if (!admin) {
      console.error("ERROR: Admin user 'admin' not found in the database.");
      db.close();
      process.exit(1);
    }

    const newPasswordHash = await bcrypt.hash(newPassword, 12);

    // Reset password and force change flag to 0
    const stmt = db.prepare("UPDATE users SET password_hash = ?, must_change_password = 0 WHERE username = 'admin'");
    const result = stmt.run(newPasswordHash);

    if (result.changes > 0) {
      console.log("✅ Admin password has been successfully reset.");
      console.log("IMPORTANT: The 'must_change_password' flag has been cleared. The admin can now log in directly.");
    } else {
      console.error("ERROR: Failed to update the admin password. No rows were changed.");
    }

    db.close();
  } catch (error) {
    console.error('An unexpected error occurred:', error);
    process.exit(1);
  }
}

resetAdminPassword();
