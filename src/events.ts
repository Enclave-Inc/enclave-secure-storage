import type {
  StorageOperation,
  StoragePlatform,
  StorageUsageRecord,
} from "./types.js";

/** Mutable last-event slot shared by all provider implementations. */
export class StorageEventSlot {
  #last: StorageUsageRecord | null = null;

  record(
    operation: StorageOperation,
    platform: StoragePlatform,
    providerName: string,
    keyIdentifier: string,
    success: boolean,
  ): void {
    this.#last = {
      operation,
      platform,
      providerName,
      keyIdentifier,
      timestamp: new Date().toISOString(),
      success,
    };
  }

  get(): StorageUsageRecord | null {
    return this.#last;
  }
}
