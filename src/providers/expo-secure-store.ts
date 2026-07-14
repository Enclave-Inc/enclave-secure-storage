/**
 * Expo SecureStore provider (iOS Keychain / Android Keystore).
 *
 * No passphrase — OS access control is the security boundary.
 *
 * Size limit: Expo documents a **2048-byte** max for stored *values* on some
 * platforms (notably Android). Values larger than that are chunked across
 * multiple SecureStore entries; we never silently truncate.
 */

import { SecretTooLargeError } from "../errors.js";
import { base64ToBytes, bytesToBase64, requireKey } from "../encoding.js";
import { StorageEventSlot } from "../events.js";
import type { SecureStorageProvider } from "../types.js";

/** Expo SecureStore documented max value length (bytes of UTF-8 string). */
export const EXPO_SECURE_STORE_MAX_VALUE_BYTES = 2048;

/** Chunk payload size leaving headroom under the 2048 limit. */
const CHUNK_PAYLOAD_BYTES = 1500;

const META_PREFIX = "ess:v1:meta:";
const CHUNK_SEP = "::chunk::";

export type ExpoSecureStoreApi = {
  setItemAsync: (
    key: string,
    value: string,
    options?: Record<string, unknown>,
  ) => Promise<void>;
  getItemAsync: (
    key: string,
    options?: Record<string, unknown>,
  ) => Promise<string | null>;
  deleteItemAsync: (
    key: string,
    options?: Record<string, unknown>,
  ) => Promise<void>;
};

export type ExpoSecureStoreProviderOptions = {
  /** Inject for tests; defaults to dynamic `expo-secure-store` import. */
  api?: ExpoSecureStoreApi;
  keychainService?: string;
};

type ChunkMeta = { v: 1; chunks: number; total: number };

export class ExpoSecureStoreProvider implements SecureStorageProvider {
  readonly #events = new StorageEventSlot();
  readonly #api: ExpoSecureStoreApi | undefined;
  readonly #options: Record<string, unknown>;

  constructor(options: ExpoSecureStoreProviderOptions = {}) {
    this.#api = options.api;
    this.#options = {
      keychainAccessible: "WHEN_UNLOCKED_THIS_DEVICE_ONLY",
      keychainService: options.keychainService ?? "enclave.secure-storage",
    };
  }

  getLastStorageEvent() {
    return this.#events.get();
  }

  async store(key: string, secret: Uint8Array): Promise<void> {
    const id = requireKey(key);
    try {
      if (!(secret instanceof Uint8Array) || secret.length === 0) {
        throw new Error("secret must be a non-empty Uint8Array");
      }
      const api = await this.#resolveApi();
      await this.#clearChunks(api, id);

      const encoded = bytesToBase64(secret);
      if (encoded.length <= EXPO_SECURE_STORE_MAX_VALUE_BYTES) {
        await api.setItemAsync(id, encoded, this.#options);
      } else {
        await this.#storeChunked(api, id, secret);
      }
      this.#events.record("store", "mobile", "expo-secure-store", id, true);
    } catch (err) {
      this.#events.record("store", "mobile", "expo-secure-store", id, false);
      throw err;
    }
  }

  async load(key: string): Promise<Uint8Array | null> {
    const id = requireKey(key);
    try {
      const api = await this.#resolveApi();
      const metaRaw = await api.getItemAsync(META_PREFIX + id, this.#options);
      let value: Uint8Array | null;
      if (metaRaw) {
        value = await this.#loadChunked(api, id, metaRaw);
      } else {
        const raw = await api.getItemAsync(id, this.#options);
        value = raw == null ? null : base64ToBytes(raw);
      }
      this.#events.record("load", "mobile", "expo-secure-store", id, true);
      return value;
    } catch (err) {
      this.#events.record("load", "mobile", "expo-secure-store", id, false);
      throw err;
    }
  }

  async remove(key: string): Promise<void> {
    const id = requireKey(key);
    try {
      const api = await this.#resolveApi();
      await this.#clearChunks(api, id);
      try {
        await api.deleteItemAsync(id, this.#options);
      } catch {
        /* missing key is fine */
      }
      this.#events.record("remove", "mobile", "expo-secure-store", id, true);
    } catch (err) {
      this.#events.record("remove", "mobile", "expo-secure-store", id, false);
      throw err;
    }
  }

  async #resolveApi(): Promise<ExpoSecureStoreApi> {
    if (this.#api) return this.#api;
    try {
      const mod = await import("expo-secure-store");
      return mod as unknown as ExpoSecureStoreApi;
    } catch {
      throw new Error(
        "expo-secure-store is required for ExpoSecureStoreProvider",
      );
    }
  }

  async #storeChunked(
    api: ExpoSecureStoreApi,
    id: string,
    secret: Uint8Array,
  ): Promise<void> {
    const chunks: Uint8Array[] = [];
    for (let i = 0; i < secret.length; i += CHUNK_PAYLOAD_BYTES) {
      chunks.push(secret.subarray(i, i + CHUNK_PAYLOAD_BYTES));
    }
    // Guard against pathological keys that cannot fit metadata either.
    const meta: ChunkMeta = {
      v: 1,
      chunks: chunks.length,
      total: secret.length,
    };
    const metaStr = JSON.stringify(meta);
    if (metaStr.length > EXPO_SECURE_STORE_MAX_VALUE_BYTES) {
      throw new SecretTooLargeError(
        secret.length,
        EXPO_SECURE_STORE_MAX_VALUE_BYTES,
        "secret metadata exceeds SecureStore limit",
      );
    }
    for (let i = 0; i < chunks.length; i += 1) {
      const payload = bytesToBase64(chunks[i]!);
      if (payload.length > EXPO_SECURE_STORE_MAX_VALUE_BYTES) {
        throw new SecretTooLargeError(
          secret.length,
          EXPO_SECURE_STORE_MAX_VALUE_BYTES,
        );
      }
      await api.setItemAsync(`${id}${CHUNK_SEP}${i}`, payload, this.#options);
    }
    await api.setItemAsync(META_PREFIX + id, metaStr, this.#options);
  }

  async #loadChunked(
    api: ExpoSecureStoreApi,
    id: string,
    metaRaw: string,
  ): Promise<Uint8Array | null> {
    const meta = JSON.parse(metaRaw) as ChunkMeta;
    if (meta.v !== 1 || !Number.isInteger(meta.chunks) || meta.chunks < 1) {
      throw new Error("corrupt SecureStore chunk metadata");
    }
    const parts: Uint8Array[] = [];
    let total = 0;
    for (let i = 0; i < meta.chunks; i += 1) {
      const raw = await api.getItemAsync(
        `${id}${CHUNK_SEP}${i}`,
        this.#options,
      );
      if (raw == null) {
        throw new Error(`missing SecureStore chunk ${i} for key`);
      }
      const part = base64ToBytes(raw);
      parts.push(part);
      total += part.length;
    }
    const out = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
      out.set(part, offset);
      offset += part.length;
    }
    return out;
  }

  async #clearChunks(api: ExpoSecureStoreApi, id: string): Promise<void> {
    const metaRaw = await api.getItemAsync(META_PREFIX + id, this.#options);
    if (metaRaw) {
      try {
        const meta = JSON.parse(metaRaw) as ChunkMeta;
        for (let i = 0; i < (meta.chunks ?? 0); i += 1) {
          try {
            await api.deleteItemAsync(
              `${id}${CHUNK_SEP}${i}`,
              this.#options,
            );
          } catch {
            /* ignore */
          }
        }
      } catch {
        /* ignore corrupt meta on clear */
      }
      try {
        await api.deleteItemAsync(META_PREFIX + id, this.#options);
      } catch {
        /* ignore */
      }
    }
  }
}
