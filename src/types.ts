/**
 * Secure storage contract — identical across web / mobile / desktop providers.
 *
 * Mirror of the CryptoProvider seam: call sites depend on
 * {@link SecureStorageProvider}; platform backends are swappable at startup.
 */

export type StoragePlatform = "mobile" | "desktop" | "web";

export type StorageOperation = "store" | "load" | "remove";

/**
 * Most recent store/load/remove on a provider instance.
 *
 * Shallow, in-memory only — same posture as pqc-primitives'
 * `getLastUsageRecord()`. This package does **not** persist, log, or
 * telemetry these records; consumers (e.g. Encrypt key-lifecycle) may.
 */
export interface StorageUsageRecord {
  operation: StorageOperation;
  platform: StoragePlatform;
  /** e.g. "expo-secure-store", "tauri-keyring", "web-passphrase" */
  providerName: string;
  /** Caller's key string — NEVER the secret bytes. */
  keyIdentifier: string;
  /** ISO 8601 */
  timestamp: string;
  success: boolean;
}

export interface SecureStorageProvider {
  store(key: string, secret: Uint8Array): Promise<void>;
  /** `null` if the key does not exist — do not throw for missing keys. */
  load(key: string): Promise<Uint8Array | null>;
  remove(key: string): Promise<void>;
  getLastStorageEvent(): StorageUsageRecord | null;
}
