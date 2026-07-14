import { describe, expect, it } from "vitest";

import { TauriKeyringProvider } from "../src/index.js";
import type { TauriKeyringBackend } from "../src/providers/tauri-keyring.js";

function memoryKeyring(): TauriKeyringBackend & { map: Map<string, string> } {
  const map = new Map<string, string>();
  return {
    map,
    async setPasswords(entries) {
      for (const e of entries) map.set(e.account, e.secret);
    },
    async getPasswords(accounts) {
      return accounts.map((a) => (map.has(a) ? map.get(a)! : null));
    },
    async deletePasswords(accounts) {
      for (const a of accounts) map.delete(a);
    },
  };
}

describe("TauriKeyringProvider (mocked backend)", () => {
  it("round-trips and records storage events", async () => {
    const backend = memoryKeyring();
    const store = new TauriKeyringProvider({ backend });
    const secret = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);

    await store.store("token", secret);
    expect(store.getLastStorageEvent()?.providerName).toBe("tauri-keyring");
    expect(store.getLastStorageEvent()?.platform).toBe("desktop");
    expect(store.getLastStorageEvent()?.success).toBe(true);

    const loaded = await store.load("token");
    expect(Array.from(loaded!)).toEqual(Array.from(secret));

    await store.remove("token");
    expect(await store.load("token")).toBeNull();
  });

  it("records success:false on induced failure", async () => {
    const backend: TauriKeyringBackend = {
      async setPasswords() {
        throw new Error("keyring unavailable");
      },
      async getPasswords() {
        return [];
      },
      async deletePasswords() {},
    };
    const store = new TauriKeyringProvider({ backend });
    await expect(store.store("k", new Uint8Array([1]))).rejects.toThrow(
      /keyring unavailable/,
    );
    expect(store.getLastStorageEvent()?.success).toBe(false);
  });
});
