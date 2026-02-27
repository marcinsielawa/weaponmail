import { InjectionToken } from '@angular/core';

/**
 * Canonical parameters for Argon2id (RFC 9106 recommended parameters for
 * interactive logins: t=2, m=64MiB, p=1).
 * PBKDF2 uses iterations only; the other fields are ignored by that strategy.
 */
export interface KdfParams {
  /** Argon2id: time cost (iterations). PBKDF2: iteration count. */
  timeCost: number;
  /** Argon2id: memory cost in KiB (e.g. 65536 = 64 MiB). Ignored by PBKDF2. */
  memoryCost: number;
  /** Argon2id: parallelism factor. Ignored by PBKDF2. */
  parallelism: number;
  /** Output key length in bytes. */
  keyLength: number;
}

/**
 * Every KDF strategy must implement this contract.
 * It receives the raw password and salt and returns a ready-to-use AES-GCM CryptoKey.
 * The implementation detail (PBKDF2 vs Argon2id) is fully encapsulated.
 */
export interface KdfStrategy {
  readonly name: string;
  deriveKey(password: string, salt: Uint8Array, params: KdfParams): Promise<CryptoKey>;
}

/** Injection token for the active KDF strategy. */
export const KDF_STRATEGY = new InjectionToken<KdfStrategy>('KDF_STRATEGY');

/** Injection token for the active KDF parameters. */
export const KDF_PARAMS = new InjectionToken<KdfParams>('KDF_PARAMS');

/** Sensible defaults — works for both strategies. */
export const DEFAULT_KDF_PARAMS: KdfParams = {
  timeCost:    2,        // Argon2id: 2 passes (RFC 9106 interactive); PBKDF2: ignored (uses own iterations const)
  memoryCost:  65_536,   // Argon2id: 64 MiB
  parallelism: 1,        // Argon2id: 1 lane (RFC 9106 interactive)
  keyLength:   32,       // 256-bit AES key
};