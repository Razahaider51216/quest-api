import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { randomUUID } from "node:crypto";
import { loadConfig } from "./config.mjs";
import { cleanupExpiredSessions, openDatabase } from "./database.mjs";
import {
  generateLicenseKey,
  hashLicenseKey,
  hashPassword,
  hashToken,
  normalizeLicenseKey,
  randomToken,
  safeEqualText,
  verifyPassword,
} from "./security.mjs";

const ADMIN_COOKIE = "aq_admin_session";
const JSON_LIMIT = 32 * 1024;
const LICENSE_SESSION_HOURS = 24 * 30;
const rateBuckets = new Map();

function nowIso() {
  return new Date().toISOString();
}

function addHours(hours) {
  return new Date(Date.now() + hours * 60 * 60 * 1000).toISOString();
}

function sendJson(response, status, body, headers = {}) {
  const payload = JSON.stringify(body);
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(payload),
    "cache-control": "no-store",
    ...headers,
  });
  response.end(payload);
}

function sendEmpty(response, status, headers = {}) {
  response.writeHead(status, { "cache-control": "no-store", ...headers });
  response.end();
}

function apiError(response, status, code, message) {
  sendJson(response, status, { error: { code, message } });
}

function setPublicCorsHeaders(response, request) {
  response.setHeader("access-control-allow-origin", request.headers.origin || "*");
  response.setHeader("access-control-allow-methods", "POST, OPTIONS");
  response.setHeader("access-control-allow-headers", "content-type, authorization");
  response.setHeader("access-control-max-age", "86400");
  response.setHeader("vary", "Origin");
}

async function readJson(request) {
  if (!String(request.headers["content-type"] ?? "").startsWith("application/json")) {
    const error = new Error("Content-Type must be application/json");
    error.status = 415;
    error.code = "UNSUPPORTED_MEDIA_TYPE";
    throw error;
  }

  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > JSON_LIMIT) {
      const error = new Error("Request body is too large");
      error.status = 413;
      error.code = "BODY_TOO_LARGE";
      throw error;
    }
    chunks.push(chunk);
  }

  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
  } catch {
    const error = new Error("Request body is not valid JSON");
    error.status = 400;
    error.code = "INVALID_JSON";
    throw error;
  }
}

function parseCookies(request) {
  const result = {};
  for (const part of String(request.headers.cookie ?? "").split(";")) {
    const separator = part.indexOf("=");
    if (separator === -1) continue;
    result[part.slice(0, separator).trim()] = decodeURIComponent(part.slice(separator + 1).trim());
  }
  return result;
}

function sessionCookie(token, production) {
  return `${ADMIN_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800${production ? "; Secure" : ""}`;
}

function clearSessionCookie(production) {
  return `${ADMIN_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${production ? "; Secure" : ""}`;
}

function clientIp(request) {
  return request.socket.remoteAddress ?? "unknown";
}

function allowAttempt(request, name, limit, windowMs) {
  const key = `${name}:${clientIp(request)}`;
  const current = Date.now();
  const bucket = rateBuckets.get(key);
  if (!bucket || current >= bucket.resetAt) {
    rateBuckets.set(key, { count: 1, resetAt: current + windowMs });
    return true;
  }
  bucket.count += 1;
  return bucket.count <= limit;
}

function assertSameOrigin(request) {
  const origin = request.headers.origin;
  if (!origin) return;
  let originHost;
  try {
    originHost = new URL(origin).host;
  } catch {
    const error = new Error("Invalid Origin header");
    error.status = 403;
    error.code = "ORIGIN_DENIED";
    throw error;
  }
  if (originHost !== request.headers.host) {
    const error = new Error("Cross-origin admin requests are not allowed");
    error.status = 403;
    error.code = "ORIGIN_DENIED";
    throw error;
  }
}

function adminFromRequest(request, database, config) {
  const token = parseCookies(request)[ADMIN_COOKIE];
  if (!token) return null;
  return database.prepare(`
    SELECT admins.id, admins.email
    FROM admin_sessions
    JOIN admins ON admins.id = admin_sessions.admin_id
    WHERE admin_sessions.token_hash = ? AND admin_sessions.expires_at > ?
  `).get(hashToken(token, config.sessionSecret), nowIso()) ?? null;
}

function requireAdmin(request, response, database, config) {
  const admin = adminFromRequest(request, database, config);
  if (!admin) {
    apiError(response, 401, "ADMIN_AUTH_REQUIRED", "Please sign in as an administrator");
    return null;
  }
  return admin;
}

function licenseView(row) {
  return {
    id: row.id,
    licenseKey: row.key_value ?? null,
    keyLast4: row.key_last4,
    label: row.label,
    status: row.status,
    role: row.role ?? "customer",
    expiresAt: row.expires_at,
    deviceLimit: row.device_limit,
    deviceCount: row.device_count ?? 0,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function getLicenseWithCount(database, id) {
  return database.prepare(`
    SELECT licenses.*, COUNT(license_devices.id) AS device_count
    FROM licenses
    LEFT JOIN license_devices ON license_devices.license_id = licenses.id
    WHERE licenses.id = ?
    GROUP BY licenses.id
  `).get(id);
}

function appSettingsView(database) {
  const rows = database.prepare("SELECT key, value, updated_at FROM app_settings").all();
  const settings = Object.fromEntries(rows.map((row) => [row.key, row.value]));
  const updatedAt = rows.reduce((latest, row) => {
    if (!latest || row.updated_at > latest) return row.updated_at;
    return latest;
  }, null);
  return {
    versionLabel: settings.version_label || "v0.10.0",
    discordContactUrl: settings.discord_contact_url || "",
    updatedAt,
  };
}

function validateDiscordContactUrl(value) {
  const text = String(value ?? "").trim();
  if (!text) return "";
  let parsed;
  try {
    parsed = new URL(text);
  } catch {
    const error = new Error("Discord contact URL must be a valid URL");
    error.status = 400;
    error.code = "INVALID_DISCORD_URL";
    throw error;
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    const error = new Error("Discord contact URL must start with http or https");
    error.status = 400;
    error.code = "INVALID_DISCORD_URL";
    throw error;
  }
  return text.slice(0, 500);
}

function saveAppSettings(database, body) {
  const versionLabel = String(body.versionLabel ?? "").trim().slice(0, 30) || "v0.10.0";
  const discordContactUrl = validateDiscordContactUrl(body.discordContactUrl);
  const updatedAt = nowIso();
  const statement = database.prepare(`
    INSERT INTO app_settings (key, value, updated_at)
    VALUES (?, ?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
  `);
  statement.run("version_label", versionLabel, updatedAt);
  statement.run("discord_contact_url", discordContactUrl, updatedAt);
  return appSettingsView(database);
}

function validateLicense(row) {
  if (!row) return { valid: false, code: "LICENSE_NOT_FOUND", message: "License key was not found" };
  if (row.status !== "active") {
    return { valid: false, code: "LICENSE_REVOKED", message: "License key has been revoked" };
  }
  if (row.expires_at && row.expires_at <= nowIso()) {
    return { valid: false, code: "LICENSE_EXPIRED", message: "License key has expired" };
  }
  return { valid: true };
}

function bearerToken(request) {
  const match = /^Bearer\s+(.+)$/i.exec(String(request.headers.authorization ?? ""));
  return match?.[1] ?? null;
}

async function serveStatic(response, config, pathname) {
  const files = {
    "/": "index.html",
    "/admin": "index.html",
    "/assets/styles.css": "styles.css",
    "/assets/app.js": "app.js",
  };
  const file = files[pathname];
  if (!file) return false;

  const contentTypes = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
  };
  const content = await readFile(resolve(config.projectDirectory, "public", file));
  response.writeHead(200, {
    "content-type": contentTypes[extname(file)],
    "content-length": content.length,
    "cache-control": file === "index.html" ? "no-store" : "public, max-age=3600",
    "content-security-policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
  });
  response.end(content);
  return true;
}

export function createApp(overrides = {}) {
  const config = loadConfig(overrides);
  const database = openDatabase(config.databasePath);
  cleanupExpiredSessions(database);

  const requestHandler = async (request, response) => {
    const url = new URL(request.url, `http://${request.headers.host ?? "localhost"}`);
    const { pathname } = url;
    const publicApiRequest = pathname.startsWith("/api/license/") || pathname === "/api/app-config";

    if (publicApiRequest) {
      setPublicCorsHeaders(response, request);
      if (request.method === "OPTIONS") {
        sendEmpty(response, 204);
        return;
      }
    }

    try {
      if (request.method === "GET" && (await serveStatic(response, config, pathname))) return;

      if (request.method === "GET" && pathname === "/api/health") {
        sendJson(response, 200, { status: "ok", service: "auto-quest-license-api" });
        return;
      }

      if (request.method === "GET" && pathname === "/api/app-config") {
        sendJson(response, 200, { app: appSettingsView(database) });
        return;
      }

      if (request.method === "GET" && pathname === "/api/setup/status") {
        const count = database.prepare("SELECT COUNT(*) AS count FROM admins").get().count;
        sendJson(response, 200, { setupRequired: count === 0 });
        return;
      }

      if (request.method === "POST" && pathname === "/api/setup") {
        assertSameOrigin(request);
        if (!allowAttempt(request, "setup", 8, 15 * 60 * 1000)) {
          apiError(response, 429, "RATE_LIMITED", "Too many setup attempts");
          return;
        }
        const count = database.prepare("SELECT COUNT(*) AS count FROM admins").get().count;
        if (count > 0) {
          apiError(response, 409, "SETUP_COMPLETE", "Administrator setup is already complete");
          return;
        }

        const body = await readJson(request);
        const email = String(body.email ?? "").trim().toLowerCase();
        const password = String(body.password ?? "");
        if (!safeEqualText(body.setupToken ?? "", config.setupToken)) {
          apiError(response, 403, "INVALID_SETUP_TOKEN", "The setup token is incorrect");
          return;
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          apiError(response, 400, "INVALID_EMAIL", "Enter a valid email address");
          return;
        }
        if (password.length < 10 || password.length > 200) {
          apiError(response, 400, "WEAK_PASSWORD", "Password must contain at least 10 characters");
          return;
        }

        const { salt, hash } = hashPassword(password);
        database.prepare(`
          INSERT INTO admins (email, password_salt, password_hash, created_at)
          VALUES (?, ?, ?, ?)
        `).run(email, salt, hash, nowIso());
        sendJson(response, 201, { created: true });
        return;
      }

      if (request.method === "POST" && pathname === "/api/admin/login") {
        assertSameOrigin(request);
        if (!allowAttempt(request, "admin-login", 10, 15 * 60 * 1000)) {
          apiError(response, 429, "RATE_LIMITED", "Too many sign-in attempts");
          return;
        }
        const body = await readJson(request);
        const email = String(body.email ?? "").trim().toLowerCase();
        const password = String(body.password ?? "");
        const admin = database.prepare("SELECT * FROM admins WHERE email = ?").get(email);
        if (!admin || !verifyPassword(password, admin.password_salt, admin.password_hash)) {
          apiError(response, 401, "INVALID_CREDENTIALS", "Email or password is incorrect");
          return;
        }

        const token = randomToken();
        const createdAt = nowIso();
        database.prepare(`
          INSERT INTO admin_sessions (token_hash, admin_id, created_at, expires_at)
          VALUES (?, ?, ?, ?)
        `).run(hashToken(token, config.sessionSecret), admin.id, createdAt, addHours(8));
        sendJson(response, 200, { admin: { id: admin.id, email: admin.email } }, {
          "set-cookie": sessionCookie(token, config.production),
        });
        return;
      }

      if (request.method === "POST" && pathname === "/api/admin/logout") {
        assertSameOrigin(request);
        const token = parseCookies(request)[ADMIN_COOKIE];
        if (token) {
          database.prepare("DELETE FROM admin_sessions WHERE token_hash = ?")
            .run(hashToken(token, config.sessionSecret));
        }
        sendEmpty(response, 204, { "set-cookie": clearSessionCookie(config.production) });
        return;
      }

      if (request.method === "GET" && pathname === "/api/admin/me") {
        const admin = requireAdmin(request, response, database, config);
        if (!admin) return;
        sendJson(response, 200, { admin });
        return;
      }

      if (request.method === "GET" && pathname === "/api/admin/settings") {
        const admin = requireAdmin(request, response, database, config);
        if (!admin) return;
        sendJson(response, 200, { app: appSettingsView(database) });
        return;
      }

      if (request.method === "PATCH" && pathname === "/api/admin/settings") {
        assertSameOrigin(request);
        const admin = requireAdmin(request, response, database, config);
        if (!admin) return;
        const body = await readJson(request);
        sendJson(response, 200, { app: saveAppSettings(database, body) });
        return;
      }

      if (request.method === "GET" && pathname === "/api/admin/licenses") {
        const admin = requireAdmin(request, response, database, config);
        if (!admin) return;
        const rows = database.prepare(`
          SELECT licenses.*, COUNT(license_devices.id) AS device_count
          FROM licenses
          LEFT JOIN license_devices ON license_devices.license_id = licenses.id
          GROUP BY licenses.id
          ORDER BY licenses.created_at DESC
        `).all();
        sendJson(response, 200, { licenses: rows.map(licenseView) });
        return;
      }

      if (request.method === "POST" && pathname === "/api/admin/licenses") {
        assertSameOrigin(request);
        const admin = requireAdmin(request, response, database, config);
        if (!admin) return;
        const body = await readJson(request);
        const label = String(body.label ?? "").trim().slice(0, 100);
        const role = body.role === "developer" ? "developer" : "customer";
        const deviceLimit = Number(body.deviceLimit ?? 1);
        const expiresInDays = body.expiresInDays === null ? null : Number(body.expiresInDays ?? 30);
        if (!Number.isInteger(deviceLimit) || deviceLimit < 1 || deviceLimit > 20) {
          apiError(response, 400, "INVALID_DEVICE_LIMIT", "Device limit must be between 1 and 20");
          return;
        }
        if (expiresInDays !== null && (!Number.isInteger(expiresInDays) || expiresInDays < 1 || expiresInDays > 3650)) {
          apiError(response, 400, "INVALID_EXPIRY", "Expiry must be between 1 and 3650 days");
          return;
        }

        const licenseKey = generateLicenseKey();
        const createdAt = nowIso();
        const expiresAt = expiresInDays === null
          ? null
          : new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000).toISOString();
        const id = randomUUID();
        database.prepare(`
          INSERT INTO licenses
            (id, key_hash, key_value, key_last4, label, status, role, expires_at, device_limit, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)
        `).run(
          id,
          hashLicenseKey(licenseKey, config.licensePepper),
          licenseKey,
          licenseKey.slice(-4),
          label,
          role,
          expiresAt,
          deviceLimit,
          createdAt,
          createdAt,
        );
        sendJson(response, 201, {
          license: licenseView(getLicenseWithCount(database, id)),
          licenseKey,
          warning: "This key is shown only once. Store it securely.",
        });
        return;
      }

      const licenseAdminMatch = /^\/api\/admin\/licenses\/([0-9a-f-]+)$/i.exec(pathname);
      if (request.method === "DELETE" && licenseAdminMatch) {
        assertSameOrigin(request);
        const admin = requireAdmin(request, response, database, config);
        if (!admin) return;
        const id = licenseAdminMatch[1];
        const existing = database.prepare("SELECT id FROM licenses WHERE id = ?").get(id);
        if (!existing) {
          apiError(response, 404, "LICENSE_NOT_FOUND", "License was not found");
          return;
        }
        database.prepare("DELETE FROM license_sessions WHERE license_id = ?").run(id);
        database.prepare("DELETE FROM license_devices WHERE license_id = ?").run(id);
        database.prepare("DELETE FROM licenses WHERE id = ?").run(id);
        sendEmpty(response, 204);
        return;
      }

      if (request.method === "PATCH" && licenseAdminMatch) {
        assertSameOrigin(request);
        const admin = requireAdmin(request, response, database, config);
        if (!admin) return;
        const id = licenseAdminMatch[1];
        const current = database.prepare("SELECT * FROM licenses WHERE id = ?").get(id);
        if (!current) {
          apiError(response, 404, "LICENSE_NOT_FOUND", "License was not found");
          return;
        }
        const body = await readJson(request);
        const status = body.status ?? current.status;
        const role = body.role === undefined ? current.role : body.role;
        const label = body.label === undefined ? current.label : String(body.label).trim().slice(0, 100);
        const deviceLimit = body.deviceLimit === undefined ? current.device_limit : Number(body.deviceLimit);
        const expiresAt = body.expiresAt === undefined ? current.expires_at : body.expiresAt;
        if (!["active", "revoked"].includes(status)) {
          apiError(response, 400, "INVALID_STATUS", "Status must be active or revoked");
          return;
        }
        if (!["customer", "developer"].includes(role)) {
          apiError(response, 400, "INVALID_ROLE", "Role must be customer or developer");
          return;
        }
        if (!Number.isInteger(deviceLimit) || deviceLimit < 1 || deviceLimit > 20) {
          apiError(response, 400, "INVALID_DEVICE_LIMIT", "Device limit must be between 1 and 20");
          return;
        }
        if (expiresAt !== null && Number.isNaN(Date.parse(expiresAt))) {
          apiError(response, 400, "INVALID_EXPIRY", "Expiry must be an ISO date or null");
          return;
        }
        database.prepare(`
          UPDATE licenses
          SET label = ?, status = ?, role = ?, expires_at = ?, device_limit = ?, updated_at = ?
          WHERE id = ?
        `).run(label, status, role, expiresAt, deviceLimit, nowIso(), id);
        if (status === "revoked") {
          database.prepare("DELETE FROM license_sessions WHERE license_id = ?").run(id);
        }
        sendJson(response, 200, { license: licenseView(getLicenseWithCount(database, id)) });
        return;
      }

      const licenseDevicesMatch = /^\/api\/admin\/licenses\/([0-9a-f-]+)\/devices$/i.exec(pathname);
      if (request.method === "DELETE" && licenseDevicesMatch) {
        assertSameOrigin(request);
        const admin = requireAdmin(request, response, database, config);
        if (!admin) return;
        const id = licenseDevicesMatch[1];
        if (!database.prepare("SELECT id FROM licenses WHERE id = ?").get(id)) {
          apiError(response, 404, "LICENSE_NOT_FOUND", "License was not found");
          return;
        }
        database.prepare("DELETE FROM license_sessions WHERE license_id = ?").run(id);
        database.prepare("DELETE FROM license_devices WHERE license_id = ?").run(id);
        sendEmpty(response, 204);
        return;
      }

      if (request.method === "POST" && pathname === "/api/license/activate") {
        if (!allowAttempt(request, "license-activate", 30, 15 * 60 * 1000)) {
          apiError(response, 429, "RATE_LIMITED", "Too many activation attempts");
          return;
        }
        const body = await readJson(request);
        const licenseKey = normalizeLicenseKey(body.licenseKey);
        const deviceId = String(body.deviceId ?? "").trim();
        const deviceName = String(body.deviceName ?? "").trim().slice(0, 100);
        if (!/^AQ-(?:[A-Z2-9]{4}-){3}[A-Z2-9]{4}$/.test(licenseKey)) {
          apiError(response, 400, "INVALID_LICENSE_FORMAT", "License key format is invalid");
          return;
        }
        if (deviceId.length < 8 || deviceId.length > 128) {
          apiError(response, 400, "INVALID_DEVICE_ID", "Device ID must contain 8 to 128 characters");
          return;
        }

        const license = database.prepare("SELECT * FROM licenses WHERE key_hash = ?")
          .get(hashLicenseKey(licenseKey, config.licensePepper));
        const state = validateLicense(license);
        if (!state.valid) {
          apiError(response, 403, state.code, state.message);
          return;
        }
        const existingDevice = database.prepare(`
          SELECT id FROM license_devices WHERE license_id = ? AND device_id = ?
        `).get(license.id, deviceId);
        if (!existingDevice) {
          const deviceCount = database.prepare(`
            SELECT COUNT(*) AS count FROM license_devices WHERE license_id = ?
          `).get(license.id).count;
          if (deviceCount >= license.device_limit) {
            apiError(response, 409, "DEVICE_LIMIT_REACHED", "This license has reached its device limit");
            return;
          }
          database.prepare(`
            INSERT INTO license_devices
              (license_id, device_id, device_name, activated_at, last_seen_at)
            VALUES (?, ?, ?, ?, ?)
          `).run(license.id, deviceId, deviceName, nowIso(), nowIso());
        } else {
          database.prepare(`
            UPDATE license_devices SET device_name = ?, last_seen_at = ? WHERE id = ?
          `).run(deviceName, nowIso(), existingDevice.id);
        }

        database.prepare("DELETE FROM license_sessions WHERE license_id = ? AND device_id = ?")
          .run(license.id, deviceId);
        const accessToken = randomToken();
        const createdAt = nowIso();
        const sessionExpiresAt = addHours(LICENSE_SESSION_HOURS);
        database.prepare(`
          INSERT INTO license_sessions
            (token_hash, license_id, device_id, created_at, expires_at, last_seen_at)
          VALUES (?, ?, ?, ?, ?, ?)
        `).run(
          hashToken(accessToken, config.sessionSecret),
          license.id,
          deviceId,
          createdAt,
          sessionExpiresAt,
          createdAt,
        );
        sendJson(response, 200, {
          accessToken,
          sessionExpiresAt,
          licenseExpiresAt: license.expires_at,
          deviceLimit: license.device_limit,
          role: license.role ?? "customer",
        });
        return;
      }

      if (request.method === "POST" && pathname === "/api/license/verify") {
        const token = bearerToken(request);
        if (!token) {
          apiError(response, 401, "LICENSE_AUTH_REQUIRED", "Bearer token is required");
          return;
        }
        const session = database.prepare(`
          SELECT license_sessions.*, licenses.status, licenses.role, licenses.expires_at AS license_expires_at,
                 licenses.device_limit
          FROM license_sessions
          JOIN licenses ON licenses.id = license_sessions.license_id
          WHERE license_sessions.token_hash = ? AND license_sessions.expires_at > ?
        `).get(hashToken(token, config.sessionSecret), nowIso());
        const state = validateLicense(session && {
          status: session.status,
          expires_at: session.license_expires_at,
        });
        if (!session || !state.valid) {
          apiError(response, 401, state.code ?? "INVALID_SESSION", state.message ?? "License session is invalid");
          return;
        }
        database.prepare("UPDATE license_sessions SET last_seen_at = ? WHERE token_hash = ?")
          .run(nowIso(), hashToken(token, config.sessionSecret));
        database.prepare(`
          UPDATE license_devices SET last_seen_at = ? WHERE license_id = ? AND device_id = ?
        `).run(nowIso(), session.license_id, session.device_id);
        sendJson(response, 200, {
          valid: true,
          sessionExpiresAt: session.expires_at,
          licenseExpiresAt: session.license_expires_at,
          deviceLimit: session.device_limit,
          role: session.role ?? "customer",
        });
        return;
      }

      if (request.method === "POST" && pathname === "/api/license/deactivate") {
        const token = bearerToken(request);
        if (!token) {
          apiError(response, 401, "LICENSE_AUTH_REQUIRED", "Bearer token is required");
          return;
        }
        const tokenHash = hashToken(token, config.sessionSecret);
        const session = database.prepare("SELECT * FROM license_sessions WHERE token_hash = ?")
          .get(tokenHash);
        if (!session) {
          apiError(response, 401, "INVALID_SESSION", "License session is invalid");
          return;
        }
        database.prepare("DELETE FROM license_sessions WHERE token_hash = ?").run(tokenHash);
        database.prepare("DELETE FROM license_devices WHERE license_id = ? AND device_id = ?")
          .run(session.license_id, session.device_id);
        sendEmpty(response, 204);
        return;
      }

      apiError(response, 404, "NOT_FOUND", "Route was not found");
    } catch (error) {
      if (error?.status) {
        apiError(response, error.status, error.code ?? "REQUEST_ERROR", error.message);
        return;
      }
      console.error(error);
      apiError(response, 500, "INTERNAL_ERROR", "The server could not process the request");
    }
  };

  const server = createServer(requestHandler);
  return {
    config,
    database,
    server,
    close: () => new Promise((resolveClose, rejectClose) => {
      server.close((error) => {
        database.close();
        if (error) rejectClose(error);
        else resolveClose();
      });
    }),
  };
}

export function startApp(overrides = {}) {
  const app = createApp(overrides);
  app.server.listen(app.config.port, app.config.host, () => {
    const address = app.server.address();
    const port = typeof address === "object" && address ? address.port : app.config.port;
    const adminCount = app.database.prepare("SELECT COUNT(*) AS count FROM admins").get().count;
    console.log(`Auto Quest License API: http://${app.config.host}:${port}`);
    if (adminCount === 0) {
      console.log("Administrator setup is required.");
      console.log(`Setup token: ${app.config.setupToken}`);
      console.log(`Open: http://${app.config.host}:${port}/admin`);
    }
  });
  return app;
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  startApp();
}
