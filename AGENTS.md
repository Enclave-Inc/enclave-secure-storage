# AGENTS.md — enclave-secure-storage

Shared secure storage for opaque secret bytes across web, Expo, and Tauri.

## Layout

```text
src/
  types.ts                 SecureStorageProvider + StorageUsageRecord
  platform.ts              getPlatformSecureStorage / detectStoragePlatform
  providers/
    expo-secure-store.ts   mobile (OS keychain) — optional peer
    tauri-keyring.ts       desktop (OS keyring) — optional peer
    web-passphrase.ts      web (IndexedDB + pqc AEAD/KDF)
tests/
```

## Commands

```bash
cd ../enclave-pqc-primitives && npm run build
cd ../enclave-secure-storage
npm install
npm test
npm run build
```

## Rules

1. Opaque bytes by key only — no product/auth concepts.
2. Do not persist / log / telemetrize `StorageUsageRecord` here.
3. Web requires a passphrase; never silent insecure fallback.
4. Mobile/desktop must not require a passphrase.
5. Keep files focused; optional peers stay optional.
