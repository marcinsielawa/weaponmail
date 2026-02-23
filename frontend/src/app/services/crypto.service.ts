import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class CryptoService {

  /**
   * Generates a random 32-byte AES key for the message body
   */
  async generateMessageKey(): Promise<CryptoKey> {
    return window.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Encrypts the body using AES-GCM
   * Returns: IV (12 bytes) + Ciphertext as Base64
   */
  async encryptBody(plainText: string, key: CryptoKey): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(plainText);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    const encrypted = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      data
    );

    // Combine IV + Ciphertext
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(encrypted), iv.length);

    return this.arrayBufferToBase64(combined);
  }

  /**
   * Generate a "Blind Token" using SHA-256
   * This is a simple hash of the sender's ID so the recipient can search for it
   * without the server knowing who sent it.
   */
  async generateBlindToken(senderId: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(senderId.toLowerCase());
    const hash = await window.crypto.subtle.digest('SHA-256', data);
    return this.arrayBufferToBase64(hash);
  }

  private arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }
}