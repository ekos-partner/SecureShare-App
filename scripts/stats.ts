import Database from "better-sqlite3";
import path from "node:path";
import fs from "node:fs";

/**
 * SECURESHARE INTERNAL STATS TOOL
 * 
 * This tool queries the database directly to provide system statistics
 * without going through the web server.
 */

const dbPath = process.env.DB_PATH || path.join(process.cwd(), "data", "secrets.db");

if (!fs.existsSync(dbPath)) {
  console.error(`Error: Database not found at ${dbPath}`);
  process.exit(1);
}

const db = new Database(dbPath, { readonly: true });

function getStats() {
  try {
    const totalSecrets = db.prepare("SELECT COUNT(*) as count FROM secrets").get() as { count: number };
    const expiredSecrets = db.prepare("SELECT COUNT(*) as count FROM secrets WHERE expires_at < CURRENT_TIMESTAMP").get() as { count: number };
    const totalViews = db.prepare("SELECT SUM(view_count) as count FROM secrets").get() as { count: number };
    
    // Get last 10 logs
    const lastLogs = db.prepare("SELECT timestamp, event, details FROM logs ORDER BY timestamp DESC LIMIT 10").all() as { timestamp: string, event: string, details: string }[];

    console.log("\n📊 SecureShare System Statistics");
    console.log("================================");
    console.log(`Total Secrets:    ${totalSecrets.count}`);
    console.log(`Expired Secrets:  ${expiredSecrets.count}`);
    console.log(`Total Views:      ${totalViews.count || 0}`);
    console.log(`Uptime:           ${Math.floor(process.uptime())} seconds`);
    console.log(`Database Path:    ${dbPath}`);
    
    console.log("\n📜 Recent System Logs");
    console.log("----------------------");
    if (lastLogs.length === 0) {
      console.log("No logs found.");
    } else {
      lastLogs.forEach(log => {
        console.log(`[${log.timestamp}] ${log.event}: ${log.details}`);
      });
    }
    console.log("");
  } catch (error) {
    console.error("Error fetching statistics:", error);
    process.exit(1);
  }
}

getStats();
