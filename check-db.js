import Database from 'better-sqlite3';
const db = new Database('data/secrets.db');
const users = db.prepare('SELECT id, username, password_hash, is_root, must_change_password FROM users').all();
console.log(JSON.stringify(users, null, 2));
