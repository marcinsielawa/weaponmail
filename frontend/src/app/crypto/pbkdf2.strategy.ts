import { Injectable } from '@angular/core';
import { KdfParams, KdfStrategy } from './kdf-strategy';

/**
 * PBKDF2-SHA256 KDF strategy.
 *
 * Uses the WebCrypto API natively — zero external dependencies, works in
 * every modern browser without WASM. Security is weaker than Argon2id
 * (not memory-hard), but is a safe fallback and useful for environments
 * where WASM is restricted (e.g. strict CSP).
 *
 * Iteration count is fixed at 600,000 (OWASP 2023 recommendation for
 * PBKDF2-SHA256) regardless of the timeCost param, which is Argon2-specific.
 */
@Injectable()
export class Pbkdf2Strategy implements KdfStrategy {

  readonly name = 'PBKDF2-SHA256';

  private static readonly ITERATIONS = 600_000;

  async deriveKey(password: string, salt: Uint8Array, params: KdfParams): Promise<CryptoKey> {
    const enc = new TextEncoder();
    const baseKey = await window.crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );

    return window.crypto.subtle.deriveKey(
      {
        name:       'PBKDF2',
        salt:       toArrayBuffer(salt),  // ← narrowed to ArrayBuffer
        iterations: Pbkdf2Strategy.ITERATIONS,
        hash:       'SHA-256',
      },
      baseKey,
      { name: 'AES-GCM', length: params.keyLength * 8 },
      false,
      ['encrypt', 'decrypt']
    );
  }
}

/**
 * Copies a Uint8Array into a guaranteed ArrayBuffer.
 * Required because TypeScript 5.9+ WebCrypto DOM types only accept
 * ArrayBufferView<ArrayBuffer>, not ArrayBufferView<ArrayBufferLike>.
 */
function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer;
}