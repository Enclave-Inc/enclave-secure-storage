/**
 * Tauri OS keyring provider (macOS Keychain / Windows Credential Manager /
 * Linux Secret Service).
 *
 * No org Tauri keyring precedent existed (Eden desktop still used
 * localStorage). This wraps `tauri-plugin-keyring-store-api` direct-account
 * APIs — OS keyring is the security boundary; no passphrase.
 */

import { base64ToBytes, bytesToBase64, requireKey } from "../encoding.js";
import { StorageEventSlot } from "../events.js";
import type { SecureStorageProvider } from "../types.js";

/** Injectable backend so CI can mock without a live OS keyring. */
export type TauriKeyringBackend = {
  setPasswords: (
    entries: Array<{ account: string; secret: string }>,
  ) => Promise<void>;
  getPasswords: (accounts: string[]) => Promise<Array<string | null>>;
  deletePasswords: (accounts: string[]) => Promise<void>;
};

export type TauriKeyringProviderOptions = {
  backend?: TauriKeyringBackend;
  /** Prefix for OS account names (default "enclave.secure-storage"). */
  accountPrefix?: string;
};

export class TauriKeyringProvider implements SecureStorageProvider {
  readonly #events = new StorageEventSlot();
  readonly #backend: TauriKeyringBackend | undefined;
  readonly #prefix: string;

  constructor(options: TauriKeyringProviderOptions = {}) {
    this.#backend = options.backend;
    this.#prefix = options.accountPrefix ?? "enclave.secure-storage";
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
      const backend = await this.#resolveBackend();
      await backend.setPasswords([
        { account: this.#account(id), secret: bytesToBase64(secret) },
      ]);
      this.#events.record("store", "desktop", "tauri-keyring", id, true);
    } catch (err) {
      this.#events.record("store", "desktop", "tauri-keyring", id, false);
      throw err;
    }
  }

  async load(key: string): Promise<Uint8Array | null> {
    const id = requireKey(key);
    try {
      const backend = await this.#resolveBackend();
      const values = await backend.getPasswords([this.#account(id)]);
      const raw = values[0] ?? null;
      const value = raw == null || raw === "" ? null : base64ToBytes(raw);
      this.#events.record("load", "desktop", "tauri-keyring", id, true);
      return value;
    } catch (err) {
      this.#events.record("load", "desktop", "tauri-keyring", id, false);
      throw err;
    }
  }

  async remove(key: string): Promise<void> {
    const id = requireKey(key);
    try {
      const backend = await this.#resolveBackend();
      await backend.deletePasswords([this.#account(id)]);
      this.#events.record("remove", "desktop", "tauri-keyring", id, true);
    } catch (err) {
      this.#events.record("remove", "desktop", "tauri-keyring", id, false);
      throw err;
    }
  }

  #account(id: string): string {
    return `${this.#prefix}.${id}`;
  }

  async #resolveBackend(): Promise<TauriKeyringBackend> {
    if (this.#backend) return this.#backend;
    try {
      const mod = await import("tauri-plugin-keyring-store-api");
      return {
        setPasswords: mod.setPasswords,
        getPasswords: mod.getPasswords,
        deletePasswords: mod.deletePasswords,
      };
    } catch {
      throw new Error(
        "tauri-plugin-keyring-store-api is required for TauriKeyringProvider",
      );
    }
  }
}
