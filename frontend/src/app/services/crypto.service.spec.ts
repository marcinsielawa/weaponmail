import { TestBed } from '@angular/core/testing';
import { CryptoService } from './crypto.service';
import { KDF_PARAMS, KDF_STRATEGY, KdfParams, KdfStrategy } from '../crypto/kdf-strategy';

/**
 * Minimal PBKDF2 KDF strategy for unit tests.
 * Uses WebCrypto with low iteration count so tests run quickly.
 * No external dependencies — avoids hash-wasm WASM loading in test environments.
 */
const testKdfStrategy: KdfStrategy = {
  name: 'test-pbkdf2',
  async deriveKey(password: string, salt: Uint8Array, params: KdfParams): Promise<CryptoKey> {
    const enc = new TextEncoder();
    const baseKey = await window.crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    const saltBuf = salt.buffer.slice(
      salt.byteOffset,
      salt.byteOffset + salt.byteLength
    ) as ArrayBuffer;
    return window.crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: saltBuf, iterations: 1, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-GCM', length: params.keyLength * 8 },
      false,
      ['encrypt', 'decrypt']
    );
  },
};

const testKdfParams: KdfParams = {
  timeCost: 1,
  memoryCost: 1,
  parallelism: 1,
  keyLength: 32,
};

describe('CryptoService', () => {
  let service: CryptoService;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      providers: [
        CryptoService,
        { provide: KDF_STRATEGY, useValue: testKdfStrategy },
        { provide: KDF_PARAMS, useValue: testKdfParams },
      ],
    }).compileComponents();
    service = TestBed.inject(CryptoService);
  });

  // ─── generateECDHKeyPair ──────────────────────────────────────────────────

  it('should generate a P-256 key pair with non-empty public and private key bytes', async () => {
    const { publicKeyBytes, privateKeyBytes } = await service.generateECDHKeyPair();
    expect(publicKeyBytes.byteLength).toBeGreaterThan(0);
    expect(privateKeyBytes.byteLength).toBeGreaterThan(0);
  });

  it('should generate unique key pairs on each call', async () => {
    const kp1 = await service.generateECDHKeyPair();
    const kp2 = await service.generateECDHKeyPair();
    // Public keys must differ (negligible probability of collision)
    expect(service.toBase64(kp1.publicKeyBytes)).not.toBe(service.toBase64(kp2.publicKeyBytes));
  });

  // ─── encryptMessage / decryptMessage ─────────────────────────────────────

  it('should round-trip message encryption and produce the original plaintext', async () => {
    const { publicKeyBytes, privateKeyBytes } = await service.generateECDHKeyPair();
    const plaintext = 'Hello, zero-knowledge world!';

    const { encryptedBody, messageKey, ephemeralPublicKey } = await service.encryptMessage(
      plaintext,
      publicKeyBytes,
      'sender@weaponmail.io'
    );

    const decrypted = await service.decryptMessage(
      encryptedBody,
      messageKey,
      ephemeralPublicKey,
      privateKeyBytes
    );

    expect(decrypted).toBe(plaintext);
  });

  it('should produce different ciphertexts for the same plaintext (random IV)', async () => {
    const { publicKeyBytes } = await service.generateECDHKeyPair();
    const plaintext = 'Determinism check';

    const result1 = await service.encryptMessage(plaintext, publicKeyBytes, 'a@a.io');
    const result2 = await service.encryptMessage(plaintext, publicKeyBytes, 'a@a.io');

    // Different ephemeral keys → different ciphertexts
    expect(result1.encryptedBody).not.toBe(result2.encryptedBody);
  });

  // ─── decryptSender ────────────────────────────────────────────────────────

  it('should return the correct sender email after decryptSender', async () => {
    const { publicKeyBytes, privateKeyBytes } = await service.generateECDHKeyPair();
    const senderEmail = 'alice@weaponmail.io';

    const { ephemeralPublicKey, encryptedSender } = await service.encryptMessage(
      'body',
      publicKeyBytes,
      senderEmail
    );

    const recovered = await service.decryptSender(
      encryptedSender,
      ephemeralPublicKey,
      privateKeyBytes
    );

    expect(recovered).toBe(senderEmail);
  });

  // ─── generateBlindToken ───────────────────────────────────────────────────

  it('should produce the same blind token for the same sender ID', async () => {
    const token1 = await service.generateBlindToken('alice@weaponmail.io');
    const token2 = await service.generateBlindToken('alice@weaponmail.io');
    expect(token1).toBe(token2);
  });

  it('should produce different blind tokens for different sender IDs', async () => {
    const tokenAlice = await service.generateBlindToken('alice@weaponmail.io');
    const tokenBob = await service.generateBlindToken('bob@weaponmail.io');
    expect(tokenAlice).not.toBe(tokenBob);
  });

  it('should be case-insensitive for blind token generation', async () => {
    const lower = await service.generateBlindToken('Alice@WeaponMail.io');
    const upper = await service.generateBlindToken('alice@weaponmail.io');
    expect(lower).toBe(upper);
  });

  // ─── generateSearchTokens ────────────────────────────────────────────────

  it('should generate different tokens for different keywords', async () => {
    const searchKey = await window.crypto.subtle.generateKey(
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const tokens = await service.generateSearchTokens(['hello', 'world'], searchKey);
    expect(tokens.length).toBe(2);
    expect(tokens[0]).not.toBe(tokens[1]);
  });

  it('should generate the same token for the same keyword and key', async () => {
    const rawKey = window.crypto.getRandomValues(new Uint8Array(32));
    const searchKey1 = await window.crypto.subtle.importKey(
      'raw',
      rawKey.buffer.slice(rawKey.byteOffset, rawKey.byteOffset + rawKey.byteLength) as ArrayBuffer,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const searchKey2 = await window.crypto.subtle.importKey(
      'raw',
      rawKey.buffer.slice(rawKey.byteOffset, rawKey.byteOffset + rawKey.byteLength) as ArrayBuffer,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const tokens1 = await service.generateSearchTokens(['secure'], searchKey1);
    const tokens2 = await service.generateSearchTokens(['secure'], searchKey2);
    expect(tokens1[0]).toBe(tokens2[0]);
  });

  // ─── hashForLogin ─────────────────────────────────────────────────────────

  it('should produce consistent output for hashForLogin', async () => {
    const hash1 = await service.hashForLogin('my-password');
    const hash2 = await service.hashForLogin('my-password');
    expect(hash1).toBe(hash2);
  });

  it('should produce different hashes for different passwords', async () => {
    const hash1 = await service.hashForLogin('password-a');
    const hash2 = await service.hashForLogin('password-b');
    expect(hash1).not.toBe(hash2);
  });

  // ─── encryptWithMasterKey / decryptWithMasterKey ─────────────────────────

  it('should round-trip encryptWithMasterKey and decryptWithMasterKey', async () => {
    const salt = window.crypto.getRandomValues(new Uint8Array(32));
    const masterKey = await service.deriveMasterKey('test-password', salt);

    const original = new TextEncoder().encode('private-key-bytes-here');
    const encrypted = await service.encryptWithMasterKey(original, masterKey);
    const decrypted = await service.decryptWithMasterKey(encrypted, masterKey);

    expect(new TextDecoder().decode(decrypted)).toBe('private-key-bytes-here');
  });

  it('should produce different ciphertexts each call (random IV)', async () => {
    const salt = window.crypto.getRandomValues(new Uint8Array(32));
    const masterKey = await service.deriveMasterKey('test-password', salt);
    const data = new TextEncoder().encode('payload');

    const enc1 = await service.encryptWithMasterKey(data, masterKey);
    const enc2 = await service.encryptWithMasterKey(data, masterKey);

    expect(enc1).not.toBe(enc2);
  });
});
