/** Optional peer typings so tsc succeeds without installing Expo/Tauri. */

declare module "expo-secure-store" {
  export function setItemAsync(
    key: string,
    value: string,
    options?: Record<string, unknown>,
  ): Promise<void>;
  export function getItemAsync(
    key: string,
    options?: Record<string, unknown>,
  ): Promise<string | null>;
  export function deleteItemAsync(
    key: string,
    options?: Record<string, unknown>,
  ): Promise<void>;
}

declare module "tauri-plugin-keyring-store-api" {
  export function setPasswords(
    entries: Array<{ account: string; secret: string }>,
  ): Promise<void>;
  export function getPasswords(
    accounts: string[],
  ): Promise<Array<string | null>>;
  export function deletePasswords(accounts: string[]): Promise<void>;
}
