import {
  createHash,
  createHmac,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from "node:crypto";

const LICENSE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

export function randomToken(bytes = 32) {
  return randomBytes(bytes).toString("base64url");
}

export function generateSetupToken() {
  return `SETUP-${randomToken(18)}`;
}

export function generateLicenseKey() {
  const bytes = randomBytes(16);
  let value = "";
  for (let index = 0; index < 16; index += 1) {
    value += LICENSE_ALPHABET[bytes[index] % LICENSE_ALPHABET.length];
  }
  return `AQ-${value.match(/.{1,4}/g).join("-")}`;
}

export function normalizeLicenseKey(value) {
  return String(value ?? "").trim().toUpperCase();
}

export function hashLicenseKey(value, pepper) {
  return createHmac("sha256", pepper)
    .update(normalizeLicenseKey(value))
    .digest("hex");
}

export function hashToken(value, secret) {
  return createHmac("sha256", secret).update(String(value)).digest("hex");
}

export function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const hash = scryptSync(password, salt, 64).toString("hex");
  return { salt, hash };
}

export function verifyPassword(password, salt, expectedHash) {
  const actual = scryptSync(password, salt, 64);
  const expected = Buffer.from(expectedHash, "hex");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export function safeEqualText(left, right) {
  const leftHash = createHash("sha256").update(String(left)).digest();
  const rightHash = createHash("sha256").update(String(right)).digest();
  return timingSafeEqual(leftHash, rightHash);
}
