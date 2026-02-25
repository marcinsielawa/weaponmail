import { Injectable } from '@angular/core';
import { KdfParams, KdfStrategy } from './kdf-strategy';

/**
 * Argon2id KDF strategy.
 *
 * Uses the `@node-rs/argon2` or `hash-wasm` library loaded lazily so the
 * WASM bundle is only fetched when this strategy is active.
 *
 * Argon2id (RFC 9106) is memory-hard, making it dramatically more resistant
 * to GPU/ASIC brute-force attacks than PBKDF2. It is the recommended KDF for
 * password-based key derivation in new systems.
 *
 * The WASM module is loaded lazily on first use so it doesn't bloat the
 * initial bundle for users on the PBKDF2 strategy.
 *
 * To install: npm install hash-wasm
 */
@Injectable()
export class Argon2idStrategy implements KdfStrategy {

  readonly name = 'Argon2id';

  async deriveKey(password: string, salt: Uint8Array, params: KdfParams): Promise<CryptoKey> {
    // Lazy-load the WASM module — only pays the cost when this strategy is active.
    const { argon2id } = await import('hash-wasm');

    const rawKeyHex: string = await argon2id({
      password,
      salt,
      iterations:   params.timeCost,
      memorySize:   params.memoryCost,   // KiB
      parallelism:  params.parallelism,
      hashLength:   params.keyLength,    // bytes
      outputType:   'hex',
    });

    // Convert hex → raw bytes → import as non-extractable AES-GCM key.
    const keyBytes = Uint8Array.from(
      rawKeyHex.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16))
    );

    return window.crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'AES-GCM', length: params.keyLength * 8 },
      false,               // non-extractable — never leaves the browser
      ['encrypt', 'decrypt']
    );
  }
}