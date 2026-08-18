import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

export function openDatabase(path) {
  mkdirSync(dirname(path), { recursive: true });
  const database = new DatabaseSync(path);
  database.exec("PRAGMA foreign_keys = ON;");
  database.exec("PRAGMA journal_mode = WAL;");
  database.exec(`
    CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL COLLATE NOCASE UNIQUE,
      password_salt TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS admin_sessions (
      token_hash TEXT PRIMARY KEY,
      admin_id INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS licenses (
      id TEXT PRIMARY KEY,
      key_hash TEXT NOT NULL UNIQUE,
      key_last4 TEXT NOT NULL,
      label TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
      role TEXT NOT NULL DEFAULT 'customer' CHECK (role IN ('customer', 'developer')),
      expires_at TEXT,
      device_limit INTEGER NOT NULL DEFAULT 1 CHECK (device_limit BETWEEN 1 AND 20),
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS license_devices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      license_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      device_name TEXT NOT NULL DEFAULT '',
      activated_at TEXT NOT NULL,
      last_seen_at TEXT NOT NULL,
      UNIQUE (license_id, device_id),
      FOREIGN KEY (license_id) REFERENCES licenses(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS license_sessions (
      token_hash TEXT PRIMARY KEY,
      license_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      last_seen_at TEXT NOT NULL,
      FOREIGN KEY (license_id) REFERENCES licenses(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS app_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL DEFAULT '',
      updated_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_license_devices_license_id
      ON license_devices(license_id);
    CREATE INDEX IF NOT EXISTS idx_license_sessions_license_id
      ON license_sessions(license_id);
  `);

  const licenseColumns = database.prepare("PRAGMA table_info(licenses)").all()
    .map((column) => column.name);
  if (!licenseColumns.includes("key_value")) {
    database.exec("ALTER TABLE licenses ADD COLUMN key_value TEXT;");
  }
  if (!licenseColumns.includes("role")) {
    database.exec("ALTER TABLE licenses ADD COLUMN role TEXT NOT NULL DEFAULT 'customer' CHECK (role IN ('customer', 'developer'));");
  }

  const now = new Date().toISOString();
  const defaults = [
    ["version_label", "v0.10.0"],
    ["discord_contact_url", ""],
  ];
  const insertSetting = database.prepare(`
    INSERT OR IGNORE INTO app_settings (key, value, updated_at)
    VALUES (?, ?, ?)
  `);
  for (const [key, value] of defaults) {
    insertSetting.run(key, value, now);
  }

  return database;
}

export function cleanupExpiredSessions(database, now = new Date().toISOString()) {
  database.prepare("DELETE FROM admin_sessions WHERE expires_at <= ?").run(now);
  database.prepare("DELETE FROM license_sessions WHERE expires_at <= ?").run(now);
}
