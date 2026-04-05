package com.weaponmail.account;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import java.util.concurrent.ConcurrentHashMap;
import java.util.UUID;

/**
 * Zero-Knowledge Account Service.
 *
 * Login philosophy:
 *   - The client sends loginHash = SHA-256(password). We compare hashes.
 *   - On success, we return the encryptedPrivateKey + passwordSalt so the
 *     client can re-derive its master key and decrypt the private key locally.
 *   - We NEVER have access to the private key or the password.
 */
@Service
public class AccountService {

    private final AccountRepository accountRepository;

    // In-memory session store. For production: replace with Redis.
    private final ConcurrentHashMap<String, String> activeSessions = new ConcurrentHashMap<>();

    public AccountService(AccountRepository accountRepository) {
        this.accountRepository = accountRepository;
    }

    /**
     * Registers a new Zero-Knowledge account.
     * The client has already:
     *   1. Generated an X25519 keypair in the browser
     *   2. Derived a master key from the password using Argon2id
     *   3. Encrypted the private key with the master key (AES-GCM)
     *   4. Hashed the password with SHA-256 for loginHash
     * We persist the result — never seeing the raw key or password.
     */
    public Mono<Void> signUp(UserAccount account) {
        account.createdAt = System.currentTimeMillis();
        return accountRepository.findById(account.username)
                .flatMap(existing -> Mono.<UserAccount>error(
                        new IllegalStateException("Username already taken: " + account.username)))
                .switchIfEmpty(accountRepository.save(account))
                .then();
    }

    /**
     * Verifies the login hash and returns a session token + encrypted key material.
     * The client will use the returned salt to re-derive its master key,
     * then decrypt the encryptedPrivateKey locally.
     */
    public Mono<AuthResponse> login(String username, String providedHash) {
        return accountRepository.findById(username)
                .switchIfEmpty(Mono.error(new RuntimeException("Unauthorized")))
                .flatMap(account -> {
                    if (!account.loginHash.equals(providedHash)) {
                        return Mono.error(new RuntimeException("Unauthorized: Invalid credentials"));
                    }
                    String token = UUID.randomUUID().toString();
                    activeSessions.put(token, username);

                    AuthResponse response = new AuthResponse();
                    response.token = token;
                    response.publicKey = account.publicKey;
                    response.encryptedPrivateKey = account.encryptedPrivateKey;
                    response.passwordSalt = account.passwordSalt;
                    return Mono.just(response);
                });
    }

    public Mono<Void> logout(String token) {
        return Mono.fromRunnable(() -> activeSessions.remove(token));
    }

    public String getUsernameByToken(String token) {
        return activeSessions.get(token);
    }

    /** Fetch a user's public key so a sender can encrypt to them. */
    public Mono<String> getPublicKey(String username) {
        return accountRepository.findById(username)
                .map(account -> account.publicKey)
                .switchIfEmpty(Mono.error(new RuntimeException("User not found: " + username)));
    }
}