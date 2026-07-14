/** Typed errors for secure-storage call sites. */

export class SecretTooLargeError extends Error {
  readonly name = "SecretTooLargeError";
  readonly byteLength: number;
  readonly maxBytes: number;

  constructor(byteLength: number, maxBytes: number, detail?: string) {
    super(
      detail ??
        `Secret is ${byteLength} bytes; storage backend limit is ${maxBytes} bytes per entry`,
    );
    this.byteLength = byteLength;
    this.maxBytes = maxBytes;
  }
}

export class PassphraseRequiredError extends Error {
  readonly name = "PassphraseRequiredError";

  constructor(message = "Web secure storage requires a passphrase") {
    super(message);
  }
}

export class InvalidKeyError extends Error {
  readonly name = "InvalidKeyError";

  constructor(message = "storage key must be a non-empty string") {
    super(message);
  }
}
