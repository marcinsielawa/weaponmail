import { inject, Injectable } from '@angular/core';
import { KDF_PARAMS, KDF_STRATEGY, KdfParams, KdfStrategy } from '../crypto/kdf-strategy';

@Injectable({ providedIn: 'root' })
export class CryptoService {

  private readonly kdf: KdfStrategy = inject(KDF_STRATEGY);
  private readonly kdfParams: KdfParams = inject(KDF_PARAMS);

  // ─── Key Generation ──────────────────────────────────────────────────────────

  /**
   * Generates an ECDH key pair using the P-256 (secp256r1) curve via the WebCrypto API.
   *
   * **Note on naming:** The backend and protocol documentation refer to "X25519" (Curve25519),
   * but the WebCrypto API does not natively support X25519/Curve25519 in all browsers.
   * This implementation uses P-256 (NIST curve), which is universally supported by WebCrypto.
   * P-256 provides equivalent security (128-bit) for ECDH key agreement purposes.
   * The method was previously named `generateX25519KeyPair()` — it is renamed here to
   * `generateECDHKeyPair()` to accurately reflect the underlying curve used.
   */
  async generateECDHKeyPair(): Promise<{ publicKeyBytes: Uint8Array; privateKeyBytes: Uint8Array }> {
    const keyPair = await window.crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey', 'deriveBits']
    );
    const publicKeyBytes = new Uint8Array(
      await window.crypto.subtle.exportKey('raw', keyPair.publicKey)
    );
    const privateKeyBytes = new Uint8Array(
      await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey)
    );
    return { publicKeyBytes, privateKeyBytes };
  }

  // ─── Master Key Derivation ─────────────────────────────────────��──────────────

  /**
   * Derives the master key from password + salt using the configured KDF strategy.
   * Callers don't need to know whether PBKDF2 or Argon2id is running underneath.
   */
  async deriveMasterKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
    return this.kdf.deriveKey(password, salt, this.kdfParams);
  }

  /**
   * Derives a dedicated HMAC key for search tokens via PBKDF2.
   * Search tokens don't protect private key material so memory-hardness
   * isn't needed here — keeping it on WebCrypto avoids unnecessary WASM cost.
   */
  async deriveSearchHmacKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
    const enc = new TextEncoder();
    const searchSalt = new Uint8Array([...salt, ...enc.encode('-search')]);
    const baseKey = await window.crypto.subtle.importKey(
      'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    return window.crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: this.buf(searchSalt), iterations: 100_000, hash: 'SHA-256' },
      baseKey,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
  }

  // ─── Private Key Encryption / Decryption ─────────────────────────────────────

  async encryptWithMasterKey(data: Uint8Array, masterKey: CryptoKey): Promise<string> {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: this.buf(iv) },
      masterKey,
      this.buf(data)  // ← fixed
    );
    const combined = new Uint8Array(12 + ciphertext.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(ciphertext), 12);
    return this.toBase64(combined);
  }

  async decryptWithMasterKey(base64: string, masterKey: CryptoKey): Promise<Uint8Array> {
    const combined = this.fromBase64(base64);
    const iv         = combined.slice(0, 12);
    const ciphertext = combined.slice(12);
    const plain = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: this.buf(iv) },
      masterKey,
      this.buf(ciphertext)
    );
    return new Uint8Array(plain);
  }

  // ─── Message Encryption (ECDH + AES-GCM) ────────────────────────────────────

  async encryptMessage(
    plainBody: string,
    recipientPublicKeyBytes: Uint8Array,
    senderEmail: string
  ): Promise<{
    encryptedBody: string;
    messageKey: string;
    ephemeralPublicKey: string;
    encryptedSender: string;
  }> {
    const recipientKey = await window.crypto.subtle.importKey(
      'raw',
      this.buf(recipientPublicKeyBytes),  // ← fixed
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );

    const ephemeral = await window.crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']
    );
    const ephemeralPublicKeyBytes = new Uint8Array(
      await window.crypto.subtle.exportKey('raw', ephemeral.publicKey)
    );

    const sharedSecret = await window.crypto.subtle.deriveKey(
      { name: 'ECDH', public: recipientKey },
      ephemeral.privateKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );

    const bodyKey = await window.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
    );

    const encryptedBody   = await this.encryptBody(plainBody, bodyKey);
    const bodyKeyBytes    = new Uint8Array(await window.crypto.subtle.exportKey('raw', bodyKey));
    const messageKey      = await this.encryptBytes(bodyKeyBytes, sharedSecret);
    const encryptedSender = await this.encryptBytes(
      new TextEncoder().encode(senderEmail), sharedSecret
    );

    return {
      encryptedBody,
      messageKey,
      ephemeralPublicKey: this.toBase64(ephemeralPublicKeyBytes),
      encryptedSender,
    };
  }

  async decryptMessage(
    encryptedBody: string,
    wrappedMessageKey: string,
    ephemeralPublicKeyBase64: string,
    recipientPrivateKeyBytes: Uint8Array
  ): Promise<string> {
    const recipientPrivKey = await window.crypto.subtle.importKey(
      'pkcs8',
      this.buf(recipientPrivateKeyBytes),  // ← fixed
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      ['deriveKey', 'deriveBits']
    );
    const ephemeralPub = await window.crypto.subtle.importKey(
      'raw',
      this.buf(this.fromBase64(ephemeralPublicKeyBase64)),  // ← fixed
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );
    const sharedSecret = await window.crypto.subtle.deriveKey(
      { name: 'ECDH', public: ephemeralPub },
      recipientPrivKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
    const bodyKeyBytes = await this.decryptBytes(wrappedMessageKey, sharedSecret);
    const bodyKey = await window.crypto.subtle.importKey(
      'raw',
      this.buf(bodyKeyBytes),  // ← fixed
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
    return this.decryptBody(encryptedBody, bodyKey);
  }

  async decryptSender(
    encryptedSender: string,
    ephemeralPublicKeyBase64: string,
    recipientPrivateKeyBytes: Uint8Array
  ): Promise<string> {
    const recipientPrivKey = await window.crypto.subtle.importKey(
      'pkcs8',
      this.buf(recipientPrivateKeyBytes),  // ← fixed
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      ['deriveKey', 'deriveBits']
    );
    const ephemeralPub = await window.crypto.subtle.importKey(
      'raw',
      this.buf(this.fromBase64(ephemeralPublicKeyBase64)),  // ← fixed
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );
    const sharedSecret = await window.crypto.subtle.deriveKey(
      { name: 'ECDH', public: ephemeralPub },
      recipientPrivKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
    const senderBytes = await this.decryptBytes(encryptedSender, sharedSecret);
    return new TextDecoder().decode(senderBytes);
  }

  // ─── Blind Tokens ─────────────────────────────────────────────────────────────

  /**
   * Generates a blind token for zero-knowledge sender search.
   *
   * Computes HMAC-SHA256(senderId.lowercase, BLIND_TOKEN_SALT) where
   * `BLIND_TOKEN_SALT` is a fixed application-level constant (not a per-user secret).
   *
   * **Security implications of the hardcoded salt:**
   * - The salt `'weaponmail-blind-token-salt-v1'` is a well-known constant — it is NOT secret.
   * - An attacker who knows a candidate sender email can precompute its token offline and
   *   probe the server's index. This is an accepted tradeoff: the server learns only the
   *   HMAC, never the raw email, preserving zero-knowledge against passive observers.
   * - Protection against enumeration relies on rate-limiting and authenticated endpoints,
   *   not on the salt being secret.
   * - If per-user isolation is needed in future, consider deriving the key from the
   *   recipient's master key instead of this shared constant.
   */
  async generateBlindToken(senderId: string): Promise<string> {
    const enc = new TextEncoder();
    // Fixed application-level constant — see JSDoc above for security implications.
    const BLIND_TOKEN_SALT = 'weaponmail-blind-token-salt-v1';
    const key = await window.crypto.subtle.importKey(
      'raw',
      enc.encode(BLIND_TOKEN_SALT),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const sig = await window.crypto.subtle.sign('HMAC', key, enc.encode(senderId.toLowerCase()));
    return this.toBase64(new Uint8Array(sig));
  }

  async generateSearchTokens(keywords: string[], searchHmacKey: CryptoKey): Promise<string[]> {
    const enc = new TextEncoder();
    const tokens: string[] = [];
    for (const kw of keywords) {
      const sig = await window.crypto.subtle.sign(
        'HMAC', searchHmacKey, enc.encode(kw.toLowerCase().trim())
      );
      tokens.push(this.toBase64(new Uint8Array(sig)));
    }
    return tokens;
  }

  extractKeywords(subject: string, body: string): string[] {
    const stopWords = new Set(['the','a','an','is','in','on','at','to','and','or','of','for']);
    const text = `${subject} ${body.slice(0, 200)}`;
    return [...new Set(
      text.toLowerCase()
        .replace(/[^a-z0-9\s]/g, '')
        .split(/\s+/)
        .filter(w => w.length > 2 && !stopWords.has(w))
    )];
  }

  // ─── Login Hash ───────────────────────────────────────────────────────────────

  async hashForLogin(password: string): Promise<string> {
    const enc = new TextEncoder();
    const hash = await window.crypto.subtle.digest('SHA-256', enc.encode(password));
    return this.toBase64(new Uint8Array(hash));
  }

  // ─── AES-GCM Primitives ───────────────────────────────────────────────────────

  async generateMessageKey(): Promise<CryptoKey> {
    return window.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
    );
  }

  async encryptBody(plainText: string, key: CryptoKey): Promise<string> {
    const enc = new TextEncoder();
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: this.buf(iv) },
      key,
      enc.encode(plainText)
    );
    const combined = new Uint8Array(12 + ciphertext.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(ciphertext), 12);
    return this.toBase64(combined);
  }

  async decryptBody(base64: string, key: CryptoKey): Promise<string> {
    const combined = this.fromBase64(base64);
    const iv         = combined.slice(0, 12);
    const ciphertext = combined.slice(12);
    const plain = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: this.buf(iv) },
      key,
      this.buf(ciphertext)
    );
    return new TextDecoder().decode(plain);
  }

  async encryptBytes(data: Uint8Array, key: CryptoKey): Promise<string> {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: this.buf(iv) },
      key,
      this.buf(data)  // ← fixed
    );
    const combined = new Uint8Array(12 + ciphertext.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(ciphertext), 12);
    return this.toBase64(combined);
  }

  async decryptBytes(base64: string, key: CryptoKey): Promise<Uint8Array> {
    const combined = this.fromBase64(base64);
    const iv         = combined.slice(0, 12);
    const ciphertext = combined.slice(12);
    const plain = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: this.buf(iv) },
      key,
      this.buf(ciphertext)
    );
    return new Uint8Array(plain);
  }

  // ─── Utilities ────────────────────────────────────────────────────────────────

  toBase64(buffer: Uint8Array): string {
    let binary = '';
    for (let i = 0; i < buffer.byteLength; i++) binary += String.fromCharCode(buffer[i]);
    return window.btoa(binary);
  }

  fromBase64(base64: string): Uint8Array {
    const binary = window.atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  /**
   * Narrows Uint8Array<ArrayBufferLike> → ArrayBuffer for WebCrypto APIs.
   *
   * TypeScript 5.9+ tightened the DOM lib types: WebCrypto functions now require
   * ArrayBufferView<ArrayBuffer> but Uint8Array's generic is the wider ArrayBufferLike,
   * which also includes SharedArrayBuffer. slice() always returns a plain ArrayBuffer,
   * so this is both type-safe and zero-copy when byteOffset === 0 and the buffer
   * isn't shared (the common case in this codebase).
   */
  private buf(u8: Uint8Array): ArrayBuffer {
    return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer;
  }
}