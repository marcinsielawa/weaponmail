import { TestBed } from '@angular/core/testing';
import { CryptoService } from './crypto.service';
import { KDF_PARAMS, KDF_STRATEGY, KdfParams, KdfStrategy } from '../crypto/kdf-strategy';

/**
 * Minimal PBKDF2 KDF strategy for unit tests.
 * Uses WebCrypto with low iteration count so tests run quickly.
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
    // Helper to narrow Uint8Array to ArrayBuffer for WebCrypto
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

  // ─── generateX25519KeyPair ────────────────────────────────────────────────

  it('should generate an X25519 key pair with non-empty public and private key bytes', async () => {
    const { publicKeyBytes, privateKeyBytes } = await service.generateX25519KeyPair();
    expect(publicKeyBytes.byteLength).toBe(32); // X25519 public keys are 32 bytes
    expect(privateKeyBytes.byteLength).toBe(32); // X25519 private keys are 32 bytes
  });

  it('should generate unique key pairs on each call', async () => {
    const kp1 = await service.generateX25519KeyPair();
    const kp2 = await service.generateX25519KeyPair();
    expect(service.toBase64(kp1.publicKeyBytes)).not.toBe(service.toBase64(kp2.publicKeyBytes));
  });

  // ─── encryptMessage / decryptMessage ─────────────────────────────────────

  it('should round-trip message encryption and produce the original plaintext', async () => {
    const { publicKeyBytes, privateKeyBytes } = await service.generateX25519KeyPair();
    const plaintext = 'Hello, X25519 world!';

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

  it('should produce different ciphertexts for the same plaintext (random ephemeral keys)', async () => {
    const { publicKeyBytes } = await service.generateX25519KeyPair();
    const plaintext = 'Determinism check';

    const result1 = await service.encryptMessage(plaintext, publicKeyBytes, 'a@a.io');
    const result2 = await service.encryptMessage(plaintext, publicKeyBytes, 'a@a.io');

    expect(result1.encryptedBody).not.toBe(result2.encryptedBody);
    expect(result1.ephemeralPublicKey).not.toBe(result2.ephemeralPublicKey);
  });

  // ─── decryptSender ───────────────────────────────────────────────────────

  it('should return the correct sender email after decryptSender', async () => {
    const { publicKeyBytes, privateKeyBytes } = await service.generateX25519KeyPair();
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

  it('should produce consistent, case-insensitive blind tokens', async () => {
    const token1 = await service.generateBlindToken('Alice@WeaponMail.io');
    const token2 = await service.generateBlindToken('alice@weaponmail.io');
    expect(token1).toBe(token2);
  });

  // ─── Master Key Operations ───────────────────────────────────────────────

  it('should round-trip encryptWithMasterKey and decryptWithMasterKey', async () => {
    const salt = window.crypto.getRandomValues(new Uint8Array(32));
    const masterKey = await service.deriveMasterKey('test-password', salt);

    const original = new TextEncoder().encode('private-key-bytes-here');
    const encrypted = await service.encryptWithMasterKey(original, masterKey);
    const decrypted = await service.decryptWithMasterKey(encrypted, masterKey);

    expect(new TextDecoder().decode(decrypted)).toBe('private-key-bytes-here');
  });
});