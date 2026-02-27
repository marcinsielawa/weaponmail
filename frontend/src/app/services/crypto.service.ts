import { inject, Injectable } from '@angular/core';
import { x25519 } from '@noble/curves/ed25519.js';
import { KDF_PARAMS, KDF_STRATEGY, KdfParams, KdfStrategy } from '../crypto/kdf-strategy';

@Injectable({ providedIn: 'root' })
export class CryptoService {

  private readonly kdf: KdfStrategy = inject(KDF_STRATEGY);
  private readonly kdfParams: KdfParams = inject(KDF_PARAMS);

  // ─── Key Generation ──────────────────────────────────────────────────────────

  /** Generates a real X25519 (Curve25519) key pair using @noble/curves. */
  async generateX25519KeyPair(): Promise<{ publicKeyBytes: Uint8Array; privateKeyBytes: Uint8Array }> {
    const privateKeyBytes = x25519.utils.randomSecretKey();
    const publicKeyBytes = x25519.getPublicKey(privateKeyBytes);
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
   *
   * Intentionally uses PBKDF2 (not the injected KDF strategy) because:
   * 1. Search tokens index keywords, not private key material — the attacker gain
   *    from cracking a search token is knowing a keyword, not the private key.
   * 2. PBKDF2 runs entirely in WebCrypto (no WASM), keeping the hot path fast when
   *    generating many search tokens during compose.
   * 3. The salt is personalised with "-search" to ensure domain separation from the
   *    master key even if the same password is used.
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

  // ─── Message Encryption (X25519 ECDH + HKDF + AES-GCM) ──────────────────────

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
    // Generate ephemeral X25519 key pair for forward secrecy
    const ephemeralPrivateKey = x25519.utils.randomSecretKey();
    const ephemeralPublicKeyBytes = x25519.getPublicKey(ephemeralPrivateKey);

    // X25519 ECDH: derive shared secret with recipient's long-term public key
    const sharedSecret = x25519.getSharedSecret(ephemeralPrivateKey, recipientPublicKeyBytes);

    // HKDF-SHA256: derive AES-GCM key from the shared secret
    const sharedKey = await this.deriveAesKeyFromSharedSecret(sharedSecret);

    const bodyKey = await window.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
    );

    const encryptedBody   = await this.encryptBody(plainBody, bodyKey);
    const bodyKeyBytes    = new Uint8Array(await window.crypto.subtle.exportKey('raw', bodyKey));
    const messageKey      = await this.encryptBytes(bodyKeyBytes, sharedKey);
    const encryptedSender = await this.encryptBytes(
      new TextEncoder().encode(senderEmail), sharedKey
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
    const ephemeralPublicKeyBytes = this.fromBase64(ephemeralPublicKeyBase64);

    // X25519 ECDH: derive shared secret using recipient's private key + ephemeral public key
    const sharedSecret = x25519.getSharedSecret(recipientPrivateKeyBytes, ephemeralPublicKeyBytes);

    // HKDF-SHA256: derive AES-GCM key from the shared secret
    const sharedKey = await this.deriveAesKeyFromSharedSecret(sharedSecret);

    const bodyKeyBytes = await this.decryptBytes(wrappedMessageKey, sharedKey);
    const bodyKey = await window.crypto.subtle.importKey(
      'raw',
      this.buf(bodyKeyBytes),
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
    const ephemeralPublicKeyBytes = this.fromBase64(ephemeralPublicKeyBase64);

    // X25519 ECDH: derive shared secret using recipient's private key + ephemeral public key
    const sharedSecret = x25519.getSharedSecret(recipientPrivateKeyBytes, ephemeralPublicKeyBytes);

    // HKDF-SHA256: derive AES-GCM key from the shared secret
    const sharedKey = await this.deriveAesKeyFromSharedSecret(sharedSecret);

    const senderBytes = await this.decryptBytes(encryptedSender, sharedKey);
    return new TextDecoder().decode(senderBytes);
  }

  /**
   * Derives an AES-256-GCM key from an X25519 shared secret via HKDF-SHA256.
   * Using HKDF adds domain separation (via the "weaponmail-v1" info string) and
   * ensures the AES key material is uniformly distributed even if the DH output
   * has bias near the group identity element.
   */
  private async deriveAesKeyFromSharedSecret(sharedSecret: Uint8Array): Promise<CryptoKey> {
    const hkdfKey = await window.crypto.subtle.importKey(
      'raw', this.buf(sharedSecret), 'HKDF', false, ['deriveKey']
    );
    return window.crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(32),
        info: new TextEncoder().encode('weaponmail-v1'),
      },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }

  // ─── Blind Tokens ─────────────────────────────────────────────────────────────

  async generateBlindToken(senderId: string): Promise<string> {
    const enc = new TextEncoder();
    const key = await window.crypto.subtle.importKey(
      'raw',
      enc.encode('weaponmail-blind-token-salt-v1'),
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

  /**
   * Generates HMAC blind-search tokens from subject words only.
   * Use this when you want to index subject keywords independently
   * (e.g. to merge with body tokens before sending to the server).
   */
  async generateSubjectTokens(subject: string, searchHmacKey: CryptoKey): Promise<string[]> {
    const stopWords = new Set(['the','a','an','is','in','on','at','to','and','or','of','for']);
    const words = [...new Set(
      subject.toLowerCase()
        .replace(/[^a-z0-9\s]/g, '')
        .split(/\s+/)
        .filter(w => w.length > 2 && !stopWords.has(w))
    )];
    return this.generateSearchTokens(words, searchHmacKey);
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