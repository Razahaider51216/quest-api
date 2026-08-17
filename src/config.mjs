import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { generateSetupToken, randomToken } from "./security.mjs";

const projectDirectory = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function loadLocalSecrets(path) {
  if (existsSync(path)) {
    return JSON.parse(readFileSync(path, "utf8"));
  }

  const secrets = {
    setupToken: generateSetupToken(),
    sessionSecret: randomToken(48),
    licensePepper: randomToken(48),
  };

  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(secrets, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
  return secrets;
}

export function loadConfig(overrides = {}) {
  const dataDirectory = resolve(
    overrides.dataDirectory ?? process.env.DATA_DIRECTORY ?? resolve(projectDirectory, "data"),
  );
  const secretPath = resolve(dataDirectory, "secrets.json");
  const localSecrets = loadLocalSecrets(secretPath);

  return {
    projectDirectory,
    dataDirectory,
    databasePath: resolve(
      overrides.databasePath ?? process.env.DATABASE_PATH ?? resolve(dataDirectory, "auto-quest.db"),
    ),
    host: overrides.host ?? process.env.HOST ?? "127.0.0.1",
    port: Number(overrides.port ?? process.env.PORT ?? 3211),
    production: (overrides.nodeEnv ?? process.env.NODE_ENV) === "production",
    setupToken: overrides.setupToken ?? process.env.SETUP_TOKEN ?? localSecrets.setupToken,
    sessionSecret:
      overrides.sessionSecret ?? process.env.SESSION_SECRET ?? localSecrets.sessionSecret,
    licensePepper:
      overrides.licensePepper ?? process.env.LICENSE_PEPPER ?? localSecrets.licensePepper,
  };
}
