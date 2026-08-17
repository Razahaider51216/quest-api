import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createApp } from "../src/server.mjs";

async function jsonRequest(baseUrl, path, options = {}) {
  const response = await fetch(`${baseUrl}${path}`, {
    ...options,
    headers: options.body
      ? { "content-type": "application/json", ...options.headers }
      : options.headers,
  });
  const body = response.status === 204 ? null : await response.json();
  return { response, body };
}

test("admin setup and complete license lifecycle", async (context) => {
  const dataDirectory = mkdtempSync(join(tmpdir(), "auto-quest-api-"));
  const app = createApp({
    dataDirectory,
    databasePath: join(dataDirectory, "test.db"),
    host: "127.0.0.1",
    port: 0,
    setupToken: "SETUP-test-token",
    sessionSecret: "test-session-secret-that-is-long-enough",
    licensePepper: "test-license-pepper-that-is-long-enough",
  });

  await new Promise((resolve) => app.server.listen(0, "127.0.0.1", resolve));
  const address = app.server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  context.after(async () => {
    await app.close();
    rmSync(dataDirectory, { recursive: true, force: true });
  });

  const corsPreflight = await fetch(`${baseUrl}/api/license/verify`, {
    method: "OPTIONS",
    headers: {
      origin: "tauri://localhost",
      "access-control-request-method": "POST",
      "access-control-request-headers": "authorization, content-type",
    },
  });
  assert.equal(corsPreflight.status, 204);
  assert.equal(corsPreflight.headers.get("access-control-allow-origin"), "tauri://localhost");

  const health = await jsonRequest(baseUrl, "/api/health");
  assert.equal(health.response.status, 200);
  assert.equal(health.body.status, "ok");

  const setup = await jsonRequest(baseUrl, "/api/setup", {
    method: "POST",
    body: JSON.stringify({
      setupToken: "SETUP-test-token",
      email: "owner@example.com",
      password: "correct-horse-battery-staple",
    }),
  });
  assert.equal(setup.response.status, 201);

  const secondSetup = await jsonRequest(baseUrl, "/api/setup", {
    method: "POST",
    body: JSON.stringify({
      setupToken: "SETUP-test-token",
      email: "attacker@example.com",
      password: "another-long-password",
    }),
  });
  assert.equal(secondSetup.response.status, 409);

  const login = await jsonRequest(baseUrl, "/api/admin/login", {
    method: "POST",
    body: JSON.stringify({ email: "owner@example.com", password: "correct-horse-battery-staple" }),
  });
  assert.equal(login.response.status, 200);
  const cookie = login.response.headers.get("set-cookie").split(";", 1)[0];

  const createLicense = await jsonRequest(baseUrl, "/api/admin/licenses", {
    method: "POST",
    headers: { cookie },
    body: JSON.stringify({ label: "Test customer", expiresInDays: 30, deviceLimit: 1 }),
  });
  assert.equal(createLicense.response.status, 201);
  assert.match(createLicense.body.licenseKey, /^AQ-(?:[A-Z2-9]{4}-){3}[A-Z2-9]{4}$/);
  assert.equal(createLicense.body.license.licenseKey, createLicense.body.licenseKey);
  assert.equal(createLicense.body.license.deviceCount, 0);

  const activation = await jsonRequest(baseUrl, "/api/license/activate", {
    method: "POST",
    body: JSON.stringify({
      licenseKey: createLicense.body.licenseKey,
      deviceId: "test-device-0001",
      deviceName: "Test PC",
    }),
  });
  assert.equal(activation.response.status, 200);
  assert.ok(activation.body.accessToken);

  const verify = await jsonRequest(baseUrl, "/api/license/verify", {
    method: "POST",
    headers: { authorization: `Bearer ${activation.body.accessToken}` },
    body: "{}",
  });
  assert.equal(verify.response.status, 200);
  assert.equal(verify.body.valid, true);

  const revoke = await jsonRequest(baseUrl, `/api/admin/licenses/${createLicense.body.license.id}`, {
    method: "PATCH",
    headers: { cookie },
    body: JSON.stringify({ status: "revoked" }),
  });
  assert.equal(revoke.response.status, 200);
  assert.equal(revoke.body.license.status, "revoked");

  const verifyAfterRevoke = await jsonRequest(baseUrl, "/api/license/verify", {
    method: "POST",
    headers: { authorization: `Bearer ${activation.body.accessToken}` },
    body: "{}",
  });
  assert.equal(verifyAfterRevoke.response.status, 401);

  const deleteLicense = await jsonRequest(baseUrl, `/api/admin/licenses/${createLicense.body.license.id}`, {
    method: "DELETE",
    headers: { cookie },
    body: "{}",
  });
  assert.equal(deleteLicense.response.status, 204);

  const licensesAfterDelete = await jsonRequest(baseUrl, "/api/admin/licenses", {
    headers: { cookie },
  });
  assert.equal(licensesAfterDelete.body.licenses.length, 0);
});
