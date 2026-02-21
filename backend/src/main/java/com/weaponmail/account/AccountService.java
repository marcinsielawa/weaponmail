package com.weaponmail.account;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import java.util.concurrent.ConcurrentHashMap;
import java.util.UUID;

@Service
public class AccountService {

    // Store users: Key = Username, Value = UserAccount
    private final ConcurrentHashMap<String, UserAccount> userDatabase = new ConcurrentHashMap<>();

    // Store active sessions: Key = Token, Value = Username
    private final ConcurrentHashMap<String, String> activeSessions = new ConcurrentHashMap<>();

    /**
     * Registers a new Zero-Knowledge account.
     */
    public Mono<Void> signUp(UserAccount account) {
        return Mono.fromRunnable(() -> {
            account.createdAt = System.currentTimeMillis();
            userDatabase.put(account.username, account);
            System.out.println("Weapon Mail: Account created for " + account.username);
        });
    }

    /**
     * Verifies the login hash and returns a session token + keys.
     */
    public Mono<AuthResponse> login(String username, String providedHash) {
        UserAccount account = userDatabase.get(username);

        if (account != null && account.loginHash.equals(providedHash)) {
            String token = UUID.randomUUID().toString();
            activeSessions.put(token, username);

            AuthResponse response = new AuthResponse();
            response.token = token;
            response.publicKey = account.publicKey;
            response.encryptedPrivateKey = account.encryptedPrivateKey;
            response.passwordSalt = account.passwordSalt;

            return Mono.just(response);
        }

        return Mono.error(new RuntimeException("Unauthorized: Invalid username or hash"));
    }

    public Mono<Void> logout(String token) {
        return Mono.fromRunnable(() -> activeSessions.remove(token));
    }

    public String getUsernameByToken(String token) {
        return activeSessions.get(token);
    }
}