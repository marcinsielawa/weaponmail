package com.weaponmail.account;

import org.springframework.data.cassandra.core.mapping.Column;
import org.springframework.data.cassandra.core.mapping.PrimaryKey;
import org.springframework.data.cassandra.core.mapping.Table;

/**
 * Zero-Knowledge UserAccount.
 * The server stores ONLY what it must — never the plaintext private key or password.
 * The encryptedPrivateKey is an opaque blob; only the client can decrypt it using
 * the Argon2id-derived master key that never leaves the browser.
 */
@Table("accounts")
public class UserAccount {

    @PrimaryKey
    public String username; // e.g., "marcin@weaponmail.io"

    /** SHA-256(password) — never the raw password. Used only to verify login. */
    @Column("login_hash")
    public String loginHash;

    /** X25519 public key (Base64). Published so others can encrypt mail to this user. */
    @Column("public_key")
    public String publicKey;

    /**
     * Private key encrypted with Argon2id-derived master key (AES-GCM, Base64).
     * The server stores this as an opaque blob. It cannot decrypt it.
     */
    @Column("encrypted_private_key")
    public String encryptedPrivateKey;

    /** Argon2id salt (Base64). Stored so the client can re-derive the master key on login. */
    @Column("password_salt")
    public String passwordSalt;

    @Column("created_at")
    public long createdAt;
}