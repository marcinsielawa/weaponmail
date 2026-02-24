import { Injectable, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { CryptoService } from './crypto.service';

export interface SignUpPayload {
  username: string;
  loginHash: string;
  publicKey: string;
  encryptedPrivateKey: string;
  passwordSalt: string;
}

export interface AuthResponse {
  token: string;
  publicKey: string;
  encryptedPrivateKey: string;
  passwordSalt: string;
}

/**
 * AuthService manages the session lifecycle.
 *
 * Security model:
 *   - The raw password NEVER leaves the browser.
 *   - loginHash (SHA-256 of password) is sent to the server only for verification.
 *   - The Argon2id master key is derived in the browser and kept in memory only.
 *   - The X25519 private key is decrypted in the browser and kept in memory only.
 *   - On page refresh / logout, the private key is cleared from memory.
 */
@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly apiUrl = '/api/account';

  // In-memory session state — never persisted to localStorage
  readonly currentUser = signal<string | null>(null);
  readonly sessionToken = signal<string | null>(null);

  // The decrypted private key (X25519, raw bytes) — lives only in memory
  privateKeyBytes = signal<Uint8Array | null>(null);
  publicKeyBytes = signal<Uint8Array | null>(null);

  constructor(private http: HttpClient, private crypto: CryptoService) {}

  /**
   * Full signup flow:
   * 1. Generate Argon2id salt
   * 2. Derive master key from password + salt (PBKDF2 as Argon2id polyfill)
   * 3. Generate X25519 keypair
   * 4. Encrypt private key with master key (AES-GCM)
   * 5. Compute loginHash = SHA-256(password)
   * 6. Send to server — server stores opaque blobs only
   */
  async signUp(username: string, password: string): Promise<void> {
    const salt = window.crypto.getRandomValues(new Uint8Array(32));
    const masterKey = await this.crypto.deriveMasterKey(password, salt);
    const { publicKeyBytes, privateKeyBytes } = await this.crypto.generateX25519KeyPair();
    const encryptedPrivateKey = await this.crypto.encryptWithMasterKey(privateKeyBytes, masterKey);
    const loginHash = await this.crypto.hashForLogin(password);
    const saltBase64 = this.crypto.toBase64(salt);
    const publicKeyBase64 = this.crypto.toBase64(publicKeyBytes);

    const payload: SignUpPayload = {
      username,
      loginHash,
      publicKey: publicKeyBase64,
      encryptedPrivateKey,
      passwordSalt: saltBase64,
    };

    await firstValueFrom(this.http.post<void>(`${this.apiUrl}/signup`, payload));

    // Auto-login after signup: store key material in memory
    this.currentUser.set(username);
    this.privateKeyBytes.set(privateKeyBytes);
    this.publicKeyBytes.set(publicKeyBytes);
  }

  /**
   * Login flow:
   * 1. Send loginHash to server
   * 2. Receive encryptedPrivateKey + passwordSalt
   * 3. Re-derive master key from password + salt
   * 4. Decrypt private key in browser
   * 5. Store session token + key material in memory
   */
  async login(username: string, password: string): Promise<void> {
    const loginHash = await this.crypto.hashForLogin(password);
    const response = await firstValueFrom(
      this.http.post<AuthResponse>(`${this.apiUrl}/login`, { username, loginHash })
    );

    const salt = this.crypto.fromBase64(response.passwordSalt);
    const masterKey = await this.crypto.deriveMasterKey(password, salt);
    const privateKeyBytes = await this.crypto.decryptWithMasterKey(
      response.encryptedPrivateKey,
      masterKey
    );
    const publicKeyBytes = this.crypto.fromBase64(response.publicKey);

    this.sessionToken.set(response.token);
    this.currentUser.set(username);
    this.privateKeyBytes.set(privateKeyBytes);
    this.publicKeyBytes.set(publicKeyBytes);
  }

  logout(): void {
    const token = this.sessionToken();
    if (token) {
      this.http.post(`${this.apiUrl}/logout`, {}, {
        headers: { Authorization: `Bearer ${token}` }
      }).subscribe();
    }
    // Zero out key material from memory
    this.sessionToken.set(null);
    this.currentUser.set(null);
    this.privateKeyBytes.set(null);
    this.publicKeyBytes.set(null);
  }

  isLoggedIn(): boolean {
    return this.currentUser() !== null;
  }
}