/**
 * `@enclave-technologies/secure-storage` — opaque secret-byte storage across platforms.
 *
 * Mobile/desktop: OS-backed (no passphrase). Web: passphrase + IndexedDB.
 * No product/auth/session concepts here.
 */

export type {
  SecureStorageProvider,
  StorageOperation,
  StoragePlatform,
  StorageUsageRecord,
} from "./types.js";

export {
  InvalidKeyError,
  PassphraseRequiredError,
  SecretTooLargeError,
} from "./errors.js";

export {
  detectStoragePlatform,
  getPlatformSecureStorage,
  type PlatformSecureStorageOptions,
} from "./platform.js";

export {
  ExpoSecureStoreProvider,
  EXPO_SECURE_STORE_MAX_VALUE_BYTES,
  type ExpoSecureStoreApi,
  type ExpoSecureStoreProviderOptions,
} from "./providers/expo-secure-store.js";

export {
  TauriKeyringProvider,
  type TauriKeyringBackend,
  type TauriKeyringProviderOptions,
} from "./providers/tauri-keyring.js";

export {
  WebPassphraseProvider,
  WEB_STORAGE_KDF_LABEL,
  type PassphraseSource,
  type WebPassphraseProviderOptions,
} from "./providers/web-passphrase.js";
