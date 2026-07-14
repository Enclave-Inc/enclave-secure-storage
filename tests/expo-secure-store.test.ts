import { describe, expect, it } from "vitest";

import {
  ExpoSecureStoreProvider,
  EXPO_SECURE_STORE_MAX_VALUE_BYTES,
} from "../src/index.js";
import type { ExpoSecureStoreApi } from "../src/providers/expo-secure-store.js";

function memoryExpoApi(): ExpoSecureStoreApi & { map: Map<string, string> } {
  const map = new Map<string, string>();
  return {
    map,
    async setItemAsync(key, value) {
      map.set(key, value);
    },
    async getItemAsync(key) {
      return map.has(key) ? map.get(key)! : null;
    },
    async deleteItemAsync(key) {
      map.delete(key);
    },
  };
}

describe("ExpoSecureStoreProvider (mocked API)", () => {
  it("round-trips and records storage events", async () => {
    const api = memoryExpoApi();
    const store = new ExpoSecureStoreProvider({ api });
    const secret = crypto.getRandomValues(new Uint8Array(32));

    await store.store("identity", secret);
    expect(store.getLastStorageEvent()?.success).toBe(true);
    expect(store.getLastStorageEvent()?.providerName).toBe("expo-secure-store");
    expect(store.getLastStorageEvent()?.platform).toBe("mobile");

    const loaded = await store.load("identity");
    expect(Array.from(loaded!)).toEqual(Array.from(secret));

    await store.remove("identity");
    expect(await store.load("identity")).toBeNull();
  });

  it("records success:false when the backend throws", async () => {
    const api: ExpoSecureStoreApi = {
      async setItemAsync() {
        throw new Error("keychain locked");
      },
      async getItemAsync() {
        return null;
      },
      async deleteItemAsync() {},
    };
    const store = new ExpoSecureStoreProvider({ api });
    await expect(store.store("k", new Uint8Array([1]))).rejects.toThrow(
      /keychain locked/,
    );
    expect(store.getLastStorageEvent()?.success).toBe(false);
    expect(store.getLastStorageEvent()?.operation).toBe("store");
  });

  it("chunks secrets that exceed the SecureStore value limit", async () => {
    const api = memoryExpoApi();
    const store = new ExpoSecureStoreProvider({ api });
    // Base64 expands ~4/3 — pick plaintext that exceeds 2048 as base64.
    const secret = crypto.getRandomValues(
      new Uint8Array(EXPO_SECURE_STORE_MAX_VALUE_BYTES),
    );
    await store.store("big", secret);
    const loaded = await store.load("big");
    expect(loaded!.length).toBe(secret.length);
    expect(Array.from(loaded!)).toEqual(Array.from(secret));
    // Meta key should exist for chunked values.
    expect(
      [...api.map.keys()].some((k) => k.startsWith("ess:v1:meta:")),
    ).toBe(true);
  });
});
