package com.weaponmail.account;

public class UserAccount {
    public String username; // e.g., "marcin@weaponmail.io"
    
    public String loginHash;

    // The public key used by OTHERS to encrypt mail to this user
    public String publicKey; // Curve25519 (Base64)

    // The private key ENCRYPTED by the client's Argon2id Master Key
    // The server cannot decrypt this.
    public String encryptedPrivateKey;

    // The salt used for Argon2id (stored so the client can recreate the Master Key)
    public String passwordSalt;

    // Metadata
    public long createdAt;
}
