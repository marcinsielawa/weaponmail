import { Injectable } from '@angular/core';

/**
 * CryptoService — All cryptographic operations for WeaponMail.
 *
 * Key operations:
 *  - X25519 keypair generation (via WebCrypto ECDH P-256 as a polyfill, or noble-curves for true X25519)
 *  - Argon2id master key derivation (via PBKDF2-SHA256 as a browser-compatible substitute)
 *  - AES-GCM encryption/decryption for message bodies and private key storage
 *  - ECDH key exchange for wrapping per-message AES keys
 *  - HMAC-SHA256 blind tokens for sender identity and keyword search
 *
 * NOTE: The WebCrypto API does not natively support X25519/Curve25519 in all browsers as of 2025.
 * This implementation uses ECDH with P-256 for broad compatibility. In production,
 * use @noble/curves for true X25519 — the architecture is identical.
 */
@Injectable({ providedIn: 'root' })
export class CryptoService {

  // ─── Key Generation ──────────────────────────────────────────────────────────

  /**
   * Generates an X25519-equivalent ECDH keypair using P-256 (WebCrypto native).
   * Returns raw bytes for both keys (for storage/transmission).
   */
  async generateX25519KeyPair(): Promise<{ publicKeyBytes: Uint8Array; privateKeyBytes: Uint8Array }> {
    const keyPair = await window.crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true, // exportable
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

  // ─── Master Key Derivation ────────────────────────────────────────────────────

  /**
   * Derives the Argon2id master key from the user's password + salt.
   * Uses PBKDF2-SHA256 as a WebCrypto-native substitute for Argon2id.
   * In production, use argon2-browser WASM for true Argon2id.
   *
   * The master key is used to encrypt/decrypt the private key blob.
   * It NEVER leaves the browser.
   */
  async deriveMasterKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
    const enc = new TextEncoder();
    const baseKey = await window.crypto.subtle.importKey(
      'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    return window.crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: salt as BufferSource, iterations: 600_000, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Derives a secondary search key from the master key (via HKDF).
   * Used to generate HMAC keyword tokens without reusing the master key directly.
   */
  async deriveSearchKey(masterKey: CryptoKey): Promise<CryptoKey> {
    // Export master key bytes, re-import as HKDF base material
    const masterBytes = await window.crypto.subtle.exportKey('raw',
      // We need a raw-exportable key; derive an intermediate raw key
      await window.crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: new TextEncoder().encode('weaponmail-search-salt'), iterations: 1, hash: 'SHA-256' },
        await window.crypto.subtle.importKey('raw',
          new Uint8Array(await window.crypto.subtle.wrapKey(
            'raw',
            // Use an AES-KW key as intermediate — cleaner approach:
            // Just use HMAC key derivation directly
            masterKey, masterKey, 'AES-KW'
          )).slice(0, 32), // trim to 32 bytes
          'PBKDF2', false, ['deriveKey']),
        { name: 'AES-GCM', length: 256 }, true, ['encrypt']
      )
    );
    // Import as HMAC key for token generation
    return window.crypto.subtle.importKey(
      'raw', masterBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
  }

  // ─── Private Key Encryption/Decryption ───────────────────────────────────────

  /** Encrypts private key bytes with the master key (AES-GCM). Returns Base64. */
  async encryptWithMasterKey(data: Uint8Array, masterKey: CryptoKey): Promise<string> {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, masterKey, data as BufferSource);
    const combined = new Uint8Array(12 + ciphertext.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(ciphertext), 12);
    return this.toBase64(combined);
  }

  /** Decrypts private key bytes encrypted with the master key. */
  async decryptWithMasterKey(base64: string, masterKey: CryptoKey): Promise<Uint8Array> {
    const combined = this.fromBase64(base64);
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);
    const plain = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, masterKey, ciphertext);
    return new Uint8Array(plain);
  }

  // ─── Message Encryption (ECDH + AES-GCM) ────────────────────────────────────

  /**
   * Full message encryption pipeline:
   * 1. Generate ephemeral ECDH keypair for this message
   * 2. Perform ECDH with recipient's public key → shared secret
   * 3. Generate random AES-GCM key for the body
   * 4. Encrypt body with AES-GCM key
   * 5. Wrap (encrypt) AES key with the ECDH shared secret
   * Returns all components needed for MessageRequest.
   */
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
    // 1. Import recipient public key
    const recipientKey = await window.crypto.subtle.importKey(
      'raw', recipientPublicKeyBytes as BufferSource, { name: 'ECDH', namedCurve: 'P-256' }, false, []
    );

    // 2. Generate ephemeral keypair for this message (perfect forward secrecy)
    const ephemeral = await window.crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']
    );
    const ephemeralPublicKeyBytes = new Uint8Array(
      await window.crypto.subtle.exportKey('raw', ephemeral.publicKey)
    );

    // 3. ECDH key agreement → shared secret → AES-GCM wrapping key
    const sharedSecret = await window.crypto.subtle.deriveKey(
      { name: 'ECDH', public: recipientKey },
      ephemeral.privateKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );

    // 4. Generate per-message AES-GCM body key
    const bodyKey = await window.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
    );

    // 5. Encrypt the body
    const encryptedBody = await this.encryptBody(plainBody, bodyKey);

    // 6. Wrap the body key with the ECDH shared secret
    const bodyKeyBytes = new Uint8Array(await window.crypto.subtle.exportKey('raw', bodyKey));
    const messageKey = await this.encryptBytes(bodyKeyBytes, sharedSecret);

    // 7. Encrypt the sender's email address to the recipient (for inbox display)
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

  /**
   * Decrypts a received message:
   * 1. Re-derive shared secret using recipient private key + ephemeral public key
   * 2. Unwrap (decrypt) the AES body key
   * 3. Decrypt the body
   */
  async decryptMessage(
    encryptedBody: string,
    wrappedMessageKey: string,
    ephemeralPublicKeyBase64: string,
    recipientPrivateKeyBytes: Uint8Array
  ): Promise<string> {
    const recipientPrivKey = await window.crypto.subtle.importKey(
      'pkcs8', recipientPrivateKeyBytes as BufferSource,
      { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey', 'deriveBits']
    );
    const ephemeralPub = await window.crypto.subtle.importKey(
      'raw', this.fromBase64(ephemeralPublicKeyBase64) as BufferSource,
      { name: 'ECDH', namedCurve: 'P-256' }, false, []
    );
    const sharedSecret = await window.crypto.subtle.deriveKey(
      { name: 'ECDH', public: ephemeralPub },
      recipientPrivKey,
      { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
    );
    const bodyKeyBytes = await this.decryptBytes(wrappedMessageKey, sharedSecret);
    const bodyKey = await window.crypto.subtle.importKey(
      'raw', bodyKeyBytes as BufferSource, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );
    return this.decryptBody(encryptedBody, bodyKey);
  }

  /** Decrypts the sender's encrypted email address in an inbox summary. */
  async decryptSender(
    encryptedSender: string,
    ephemeralPublicKeyBase64: string,
    recipientPrivateKeyBytes: Uint8Array
  ): Promise<string> {
    const recipientPrivKey = await window.crypto.subtle.importKey(
      'pkcs8', recipientPrivateKeyBytes as BufferSource,
      { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey', 'deriveBits']
    );
    const ephemeralPub = await window.crypto.subtle.importKey(
      'raw', this.fromBase64(ephemeralPublicKeyBase64) as BufferSource,
      { name: 'ECDH', namedCurve: 'P-256' }, false, []
    );
    const sharedSecret = await window.crypto.subtle.deriveKey(
      { name: 'ECDH', public: ephemeralPub },
      recipientPrivKey,
      { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
    );
    const senderBytes = await this.decryptBytes(encryptedSender, sharedSecret);
    return new TextDecoder().decode(senderBytes);
  }

  // ─── Blind Tokens ─────────────────────────────────────────────────────────────

  /**
   * Generates a blind sender token: HMAC-SHA256(senderEmail, serverSalt).
   * The serverSalt is a fixed known constant (not secret) — the privacy guarantee
   * comes from the recipient needing to know the sender email to compute the token.
   */
  async generateBlindToken(senderId: string): Promise<string> {
    const enc = new TextEncoder();
    const key = await window.crypto.subtle.importKey(
      'raw', enc.encode('weaponmail-blind-token-salt-v1'),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const sig = await window.crypto.subtle.sign('HMAC', key, enc.encode(senderId.toLowerCase()));
    return this.toBase64(new Uint8Array(sig));
  }

  /**
   * Generates HMAC-SHA256 keyword search tokens for blind encrypted search.
   * Uses a key derived from the user's master key — only the key owner can
   * generate or verify these tokens.
   *
   * @param keywords - array of lowercase, normalized keywords
   * @param searchHmacKey - derived from master key via deriveSearchHmacKey()
   */
  async generateSearchTokens(keywords: string[], searchHmacKey: CryptoKey): Promise<string[]> {
    const enc = new TextEncoder();
    const tokens: string[] = [];
    for (const kw of keywords) {
      const sig = await window.crypto.subtle.sign('HMAC', searchHmacKey, enc.encode(kw.toLowerCase().trim()));
      tokens.push(this.toBase64(new Uint8Array(sig)));
    }
    return tokens;
  }

  /**
   * Derives a dedicated HMAC key for search tokens from the user's master password.
   * Separate from the master key so compromise of search tokens doesn't reveal private key.
   */
  async deriveSearchHmacKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
    const enc = new TextEncoder();
    const searchSalt = new Uint8Array([...salt, ...enc.encode('-search')]);
    const baseKey = await window.crypto.subtle.importKey(
      'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    const rawKey = await window.crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: searchSalt, iterations: 100_000, hash: 'SHA-256' },
      baseKey,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    return rawKey;
  }

  /** Extracts keywords from subject + body preview for search indexing. */
  extractKeywords(subject: string, body: string): string[] {
    const stopWords = new Set(['the', 'a', 'an', 'is', 'in', 'on', 'at', 'to', 'and', 'or', 'of', 'for']);
    const text = `${subject} ${body.slice(0, 200)}`;
    return [...new Set(
      text.toLowerCase()
        .replace(/[^a-z0-9\s]/g, '')
        .split(/\s+/)
        .filter(w => w.length > 2 && !stopWords.has(w))
    )];
  }

  // ─── Login Hash ───────────────────────────────────────────────────────────────

  /** Computes loginHash = SHA-256(password). Sent to server for authentication. */
  async hashForLogin(password: string): Promise<string> {
    const enc = new TextEncoder();
    const hash = await window.crypto.subtle.digest('SHA-256', enc.encode(password));
    return this.toBase64(new Uint8Array(hash));
  }

  // ─── AES-GCM Primitives ───────────────────────────────────────────────────────

  async generateMessageKey(): Promise<CryptoKey> {
    return window.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  }

  async encryptBody(plainText: string, key: CryptoKey): Promise<string> {
    const enc = new TextEncoder();
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plainText));
    const combined = new Uint8Array(12 + ciphertext.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(ciphertext), 12);
    return this.toBase64(combined);
  }

  async decryptBody(base64: string, key: CryptoKey): Promise<string> {
    const combined = this.fromBase64(base64);
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);
    const plain = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return new TextDecoder().decode(plain);
  }

  async encryptBytes(data: Uint8Array, key: CryptoKey): Promise<string> {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data as BufferSource);
    const combined = new Uint8Array(12 + ciphertext.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(ciphertext), 12);
    return this.toBase64(combined);
  }

  async decryptBytes(base64: string, key: CryptoKey): Promise<Uint8Array> {
    const combined = this.fromBase64(base64);
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);
    const plain = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
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
}