import "fake-indexeddb/auto";
import { beforeAll, describe, expect, it } from "vitest";
import { runSelfTests } from "@enclave-technologies/pqc-primitives";

import {
  PassphraseRequiredError,
  WebPassphraseProvider,
  getPlatformSecureStorage,
} from "../src/index.js";

beforeAll(async () => {
  await runSelfTests();
});

describe("WebPassphraseProvider", () => {
  it("round-trips encrypt/decrypt via IndexedDB", async () => {
    const store = new WebPassphraseProvider({
      passphrase: "correct horse battery staple",
      dbName: "ess-test-roundtrip",
    });
    const key = "seed:user@example.com";
    const secret = crypto.getRandomValues(new Uint8Array(32));

    await store.store(key, secret);
    const loaded = await store.load(key);
    expect(loaded).not.toBeNull();
    expect(Array.from(loaded!)).toEqual(Array.from(secret));

    const ev = store.getLastStorageEvent();
    expect(ev?.operation).toBe("load");
    expect(ev?.providerName).toBe("web-passphrase");
    expect(ev?.platform).toBe("web");
    expect(ev?.keyIdentifier).toBe(key);
    expect(ev?.success).toBe(true);
    expect(ev?.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it("uses a fresh nonce on each store()", async () => {
    const store = new WebPassphraseProvider({
      passphrase: "nonce-test-pass",
      dbName: "ess-test-nonce",
    });
    const key = "k";
    const secret = new Uint8Array([1, 2, 3, 4, 5]);

    // Peek at stored rows via a second provider sharing the DB name / factory.
    const nonces: string[] = [];
    for (let i = 0; i < 3; i += 1) {
      await store.store(key, secret);
      const db = await openDb("ess-test-nonce");
      const row = await getRow(db, key);
      db.close();
      nonces.push(row!.nonceB64);
    }
    expect(new Set(nonces).size).toBe(3);
  });

  it("returns null for missing keys without throwing", async () => {
    const store = new WebPassphraseProvider({
      passphrase: "missing-key-pass",
      dbName: "ess-test-missing",
    });
    await expect(store.load("nope")).resolves.toBeNull();
    expect(store.getLastStorageEvent()?.success).toBe(true);
  });

  it("records success:false on induced load failure (wrong passphrase)", async () => {
    const dbName = "ess-test-fail";
    const writer = new WebPassphraseProvider({
      passphrase: "right-pass",
      dbName,
    });
    await writer.store("k", new Uint8Array([9, 9, 9]));

    const reader = new WebPassphraseProvider({
      passphrase: "wrong-pass",
      dbName,
    });
    await expect(reader.load("k")).rejects.toBeTruthy();
    const ev = reader.getLastStorageEvent();
    expect(ev?.operation).toBe("load");
    expect(ev?.success).toBe(false);
    expect(ev?.providerName).toBe("web-passphrase");
  });

  it("remove deletes the row", async () => {
    const store = new WebPassphraseProvider({
      passphrase: "rm-pass",
      dbName: "ess-test-rm",
    });
    await store.store("k", new Uint8Array([1]));
    await store.remove("k");
    expect(store.getLastStorageEvent()?.operation).toBe("remove");
    expect(store.getLastStorageEvent()?.success).toBe(true);
    await expect(store.load("k")).resolves.toBeNull();
  });
});

describe("getPlatformSecureStorage (web)", () => {
  it("throws PassphraseRequiredError without a passphrase", () => {
    expect(() => getPlatformSecureStorage()).toThrow(PassphraseRequiredError);
  });

  it("returns a web provider when passphrase is supplied", async () => {
    const store = getPlatformSecureStorage({ passphrase: "p" });
    await store.store("a", new Uint8Array([7]));
    expect(store.getLastStorageEvent()?.providerName).toBe("web-passphrase");
  });
});

function openDb(name: string): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(name, 1);
    req.onerror = () => reject(req.error);
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains("secrets")) {
        req.result.createObjectStore("secrets");
      }
    };
    req.onsuccess = () => resolve(req.result);
  });
}

function getRow(
  db: IDBDatabase,
  id: string,
): Promise<{ nonceB64: string; ciphertextB64: string } | undefined> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction("secrets", "readonly");
    const req = tx.objectStore("secrets").get(id);
    req.onerror = () => reject(req.error);
    req.onsuccess = () => resolve(req.result);
  });
}
