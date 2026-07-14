import { PassphraseRequiredError } from "./errors.js";
import { ExpoSecureStoreProvider } from "./providers/expo-secure-store.js";
import { TauriKeyringProvider } from "./providers/tauri-keyring.js";
import {
  WebPassphraseProvider,
  type PassphraseSource,
} from "./providers/web-passphrase.js";
import type { SecureStorageProvider, StoragePlatform } from "./types.js";

export type PlatformSecureStorageOptions = {
  /**
   * Required on web: passphrase string or async getter.
   * Ignored on mobile/desktop (OS keyring does not need it).
   */
  passphrase?: PassphraseSource;
};

/** Detect runtime: React Native / Expo → mobile, Tauri → desktop, else web. */
export function detectStoragePlatform(): StoragePlatform {
  const g = globalThis as Record<string, unknown>;

  // React Native / Expo
  const nav = g.navigator as { product?: string } | undefined;
  if (nav?.product === "ReactNative") return "mobile";
  if (typeof g.expo !== "undefined") return "mobile";

  // Tauri 1.x / 2.x
  if (typeof g.window === "object" && g.window != null) {
    const w = g.window as Record<string, unknown>;
    if ("__TAURI_INTERNALS__" in w || "__TAURI__" in w) return "desktop";
  }
  if (typeof g.__TAURI_INTERNALS__ !== "undefined") return "desktop";
  if (typeof g.__TAURI__ !== "undefined") return "desktop";

  return "web";
}

/**
 * Return the right {@link SecureStorageProvider} for this runtime.
 * Throws {@link PassphraseRequiredError} on web if no passphrase is provided
 * — never silently falls back to an insecure store.
 */
export function getPlatformSecureStorage(
  opts: PlatformSecureStorageOptions = {},
): SecureStorageProvider {
  const platform = detectStoragePlatform();
  if (platform === "mobile") {
    return new ExpoSecureStoreProvider();
  }
  if (platform === "desktop") {
    return new TauriKeyringProvider();
  }
  if (opts.passphrase == null) {
    throw new PassphraseRequiredError(
      "getPlatformSecureStorage on web requires opts.passphrase " +
        "(string or async getter) — refusing insecure default",
    );
  }
  return new WebPassphraseProvider({ passphrase: opts.passphrase });
}
