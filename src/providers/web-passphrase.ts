/**
 * Web passphrase provider — IndexedDB + AES-256-GCM.
 *
 * Meaningfully weaker than OS-backed providers: passphrases can be guessed
 * or phished, and IndexedDB is not hardware-isolated. WebAuthn-bound storage
 * is the natural v2 upgrade for this provider (same {@link SecureStorageProvider}
 * interface — do not change call sites for that upgrade).
 *
 * This package never persists the passphrase.
 */

import {
  AEAD,
  aeadDecrypt,
  aeadEncrypt,
  labeledKdf,
} from "@enclave-technologies/pqc-primitives";

import { PassphraseRequiredError } from "../errors.js";
import {
  base64ToBytes,
  bytesToBase64,
  requireKey,
  utf8Bytes,
} from "../encoding.js";
import { StorageEventSlot } from "../events.js";
import type { SecureStorageProvider } from "../types.js";

/** Domain-separated KDF label for sealed IndexedDB secrets. */
export const WEB_STORAGE_KDF_LABEL = "enclave-secure-storage:v1" as const;

const DB_NAME = "enclave-secure-storage";
const STORE_NAME = "secrets";
const DB_VERSION = 1;

export type PassphraseSource = string | (() => Promise<string>);

export type WebPassphraseProviderOptions = {
  passphrase: PassphraseSource;
  /** Override IndexedDB factory (tests). */
  indexedDB?: IDBFactory;
  dbName?: string;
};

type StoredRow = {
  nonceB64: string;
  ciphertextB64: string;
};

export class WebPassphraseProvider implements SecureStorageProvider {
  readonly #events = new StorageEventSlot();
  readonly #passphrase: PassphraseSource;
  readonly #indexedDB: IDBFactory;
  readonly #dbName: string;
  #derivedKey: Uint8Array | null = null;

  constructor(options: WebPassphraseProviderOptions) {
    if (options.passphrase == null) {
      throw new PassphraseRequiredError();
    }
    this.#passphrase = options.passphrase;
    this.#indexedDB = options.indexedDB ?? globalThis.indexedDB;
    if (!this.#indexedDB) {
      throw new Error("IndexedDB is not available in this environment");
    }
    this.#dbName = options.dbName ?? DB_NAME;
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
      const aesKey = await this.#aesKey();
      const nonce = new Uint8Array(AEAD.NONCE_BYTES);
      crypto.getRandomValues(nonce);
      const ciphertext = aeadEncrypt(
        aesKey,
        nonce,
        secret,
        utf8Bytes(id),
      );
      await this.#put(id, {
        nonceB64: bytesToBase64(nonce),
        ciphertextB64: bytesToBase64(ciphertext),
      });
      this.#events.record("store", "web", "web-passphrase", id, true);
    } catch (err) {
      this.#events.record("store", "web", "web-passphrase", id, false);
      throw err;
    }
  }

  async load(key: string): Promise<Uint8Array | null> {
    const id = requireKey(key);
    try {
      const row = await this.#get(id);
      if (!row) {
        this.#events.record("load", "web", "web-passphrase", id, true);
        return null;
      }
      const aesKey = await this.#aesKey();
      const plaintext = aeadDecrypt(
        aesKey,
        base64ToBytes(row.nonceB64),
        base64ToBytes(row.ciphertextB64),
        utf8Bytes(id),
      );
      this.#events.record("load", "web", "web-passphrase", id, true);
      return plaintext;
    } catch (err) {
      this.#events.record("load", "web", "web-passphrase", id, false);
      throw err;
    }
  }

  async remove(key: string): Promise<void> {
    const id = requireKey(key);
    try {
      await this.#delete(id);
      this.#events.record("remove", "web", "web-passphrase", id, true);
    } catch (err) {
      this.#events.record("remove", "web", "web-passphrase", id, false);
      throw err;
    }
  }

  async #aesKey(): Promise<Uint8Array> {
    if (this.#derivedKey) return this.#derivedKey;
    const phrase =
      typeof this.#passphrase === "function"
        ? await this.#passphrase()
        : this.#passphrase;
    if (typeof phrase !== "string" || phrase.length === 0) {
      throw new PassphraseRequiredError("passphrase must be a non-empty string");
    }
    this.#derivedKey = labeledKdf(
      WEB_STORAGE_KDF_LABEL,
      utf8Bytes(phrase),
      AEAD.KEY_BYTES,
    );
    return this.#derivedKey;
  }

  #openDb(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const req = this.#indexedDB.open(this.#dbName, DB_VERSION);
      req.onerror = () => reject(req.error ?? new Error("IndexedDB open failed"));
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          db.createObjectStore(STORE_NAME);
        }
      };
      req.onsuccess = () => resolve(req.result);
    });
  }

  async #put(id: string, row: StoredRow): Promise<void> {
    const db = await this.#openDb();
    try {
      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, "readwrite");
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error ?? new Error("IndexedDB put failed"));
        tx.objectStore(STORE_NAME).put(row, id);
      });
    } finally {
      db.close();
    }
  }

  async #get(id: string): Promise<StoredRow | null> {
    const db = await this.#openDb();
    try {
      return await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, "readonly");
        const req = tx.objectStore(STORE_NAME).get(id);
        req.onerror = () =>
          reject(req.error ?? new Error("IndexedDB get failed"));
        req.onsuccess = () => {
          resolve((req.result as StoredRow | undefined) ?? null);
        };
      });
    } finally {
      db.close();
    }
  }

  async #delete(id: string): Promise<void> {
    const db = await this.#openDb();
    try {
      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, "readwrite");
        tx.oncomplete = () => resolve();
        tx.onerror = () =>
          reject(tx.error ?? new Error("IndexedDB delete failed"));
        tx.objectStore(STORE_NAME).delete(id);
      });
    } finally {
      db.close();
    }
  }
}
