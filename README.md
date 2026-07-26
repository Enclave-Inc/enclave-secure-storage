# @enclave/secure-storage

Cross-platform storage for **opaque secret bytes** (key seeds, tokens, etc.)
so product apps do not each reinvent web / mobile / desktop backends.

## Security model (honest differences)

| Platform | Provider | Passphrase? | Assurance |
|----------|----------|-------------|-----------|
| **Mobile** (Expo / RN) | `ExpoSecureStoreProvider` → iOS Keychain / Android Keystore | No | OS access control |
| **Desktop** (Tauri) | `TauriKeyringProvider` → OS credential store via `tauri-plugin-keyring-store` | No | OS access control |
| **Web** | `WebPassphraseProvider` → IndexedDB + AES-256-GCM | **Yes** | Weaker: passphrase can be guessed/phished; IndexedDB is not hardware-isolated |

Call sites use one interface (`SecureStorageProvider`). Pick the provider once at
startup (`getPlatformSecureStorage`) — do not branch on platform in store/load
call sites.

### Web is weaker — planned v2

WebAuthn-bound storage (platform authenticator) is the natural upgrade for the
**web** provider only. The interface stays stable so that upgrade should not
require call-site changes. It is **not** implemented in this package yet.

## `StorageUsageRecord` (CBOM-style seam)

`getLastStorageEvent()` returns the most recent operation on that provider
instance (including failures with `success: false`). Records are **not**
persisted, logged, or sent anywhere by this package — same posture as
`@enclave/pqc-primitives` `getLastUsageRecord()`. Future consumers (e.g.
Encrypt key-lifecycle) may read them.

`providerName` distinguishes assurance levels (`expo-secure-store` /
`tauri-keyring` / `web-passphrase`).

## Install

```bash
npm install @enclave/secure-storage
# peers as needed:
#   expo-secure-store
#   tauri-plugin-keyring-store-api  (+ Rust crate tauri-plugin-keyring-store)
```

`@enclave/pqc-primitives` is installed automatically (web provider). For local
development before npm publish:

```bash
cd ../enclave-pqc-primitives && npm run build
cd ../enclave-secure-storage
npm install
npm install ../enclave-pqc-primitives
```

## Usage

```ts
import { getPlatformSecureStorage } from "@enclave/secure-storage";

// Web must supply a passphrase (or async getter). Mobile/desktop ignore it.
const storage = getPlatformSecureStorage({
  passphrase: async () => promptUser(),
});

await storage.store("auth:seed:user@example.com", seedBytes);
const seed = await storage.load("auth:seed:user@example.com"); // null if missing
await storage.remove("auth:seed:user@example.com");

const last = storage.getLastStorageEvent();
```

### Expo size limits

`expo-secure-store` caps some platform values at **2048 bytes**. This provider
**chunks** larger secrets across multiple entries (never silently truncates).
If chunking cannot proceed, it throws `SecretTooLargeError`.

### Tauri wiring

No prior Enclave/Eden Tauri keyring existed (desktop still used localStorage).
This package uses [`tauri-plugin-keyring-store`](https://github.com/s00d/tauri-plugin-keyring-store)
(OS Keychain / Credential Manager / Secret Service). Host apps must:

1. Add the Rust plugin to `src-tauri`
2. Install `tauri-plugin-keyring-store-api`

### Testing limitations (README — intentional)

| Provider | CI coverage |
|----------|-------------|
| Web | Real `@enclave/pqc-primitives` + `fake-indexeddb` |
| Expo / Tauri | **Mocked** backends — live OS keyrings are not exercised in CI |

## License

**Apache-2.0** — see [`LICENSE`](./LICENSE).

## Scope (non-goals)
- No Encrypt integration or telemetry for `StorageUsageRecord`
- No WebAuthn provider in this version
