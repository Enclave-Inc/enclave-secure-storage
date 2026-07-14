/** Base64 helpers (no product/crypto suite dependency). */

const ENC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function bytesToBase64(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i]!;
    const b = i + 1 < bytes.length ? bytes[i + 1]! : 0;
    const c = i + 2 < bytes.length ? bytes[i + 2]! : 0;
    const triple = (a << 16) | (b << 8) | c;
    out += ENC[(triple >> 18) & 63];
    out += ENC[(triple >> 12) & 63];
    out += i + 1 < bytes.length ? ENC[(triple >> 6) & 63] : "=";
    out += i + 2 < bytes.length ? ENC[triple & 63] : "=";
  }
  return out;
}

export function base64ToBytes(b64: string): Uint8Array {
  const clean = b64.replace(/\s+/g, "");
  if (clean.length % 4 !== 0) {
    throw new Error("invalid base64 length");
  }
  const lookup = new Uint8Array(256);
  for (let i = 0; i < ENC.length; i += 1) {
    lookup[ENC.charCodeAt(i)] = i;
  }
  const pad = clean.endsWith("==") ? 2 : clean.endsWith("=") ? 1 : 0;
  const out = new Uint8Array((clean.length / 4) * 3 - pad);
  let o = 0;
  for (let i = 0; i < clean.length; i += 4) {
    const n =
      (lookup[clean.charCodeAt(i)]! << 18) |
      (lookup[clean.charCodeAt(i + 1)]! << 12) |
      (lookup[clean.charCodeAt(i + 2)]! << 6) |
      lookup[clean.charCodeAt(i + 3)]!;
    if (o < out.length) out[o++] = (n >> 16) & 255;
    if (o < out.length) out[o++] = (n >> 8) & 255;
    if (o < out.length) out[o++] = n & 255;
  }
  return out;
}

export function utf8Bytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function requireKey(key: string): string {
  const trimmed = typeof key === "string" ? key.trim() : "";
  if (!trimmed) {
    // Late import avoided — callers catch Error; typed name for instanceof.
    const err = new Error("storage key must not be empty");
    err.name = "InvalidKeyError";
    throw err;
  }
  return trimmed;
}
