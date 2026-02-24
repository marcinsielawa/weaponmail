package com.weaponmail.account;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

/**
 * Unit tests for AccountService.
 *
 * Uses Mockito to stub AccountRepository so no Spring context or
 * live ScyllaDB is required. Tests are fast, hermetic, and always green.
 */
@ExtendWith(MockitoExtension.class)
public class AccountServiceTest {

    @Mock
    private AccountRepository accountRepository;

    private AccountService accountService;

    @BeforeEach
    void setup() {
        accountService = new AccountService(accountRepository);
    }

    // ── Helper ───────────────────���────────────────────────────────────────────

    private UserAccount buildTestAccount(String username, String loginHash) {
        UserAccount account = new UserAccount();
        account.username           = username;
        account.loginHash          = loginHash;
        account.publicKey          = "pub-key-25519";
        account.encryptedPrivateKey = "locked-chest-123";
        account.passwordSalt       = "salt-xyz";
        return account;
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    @Test
    void shouldRegisterAndLoginUser() {
        UserAccount account = buildTestAccount("marcin@weaponmail.io", "correct-hash");

        // Repository: username not yet taken → empty, then save succeeds
        when(accountRepository.findById(eq("marcin@weaponmail.io")))
                .thenReturn(Mono.empty());   // not taken
        when(accountRepository.save(any(UserAccount.class)))
                .thenReturn(Mono.just(account));

        StepVerifier.create(accountService.signUp(account))
                .verifyComplete();

        // Repository: login read
        when(accountRepository.findById(eq("marcin@weaponmail.io")))
                .thenReturn(Mono.just(account));

        StepVerifier.create(accountService.login("marcin@weaponmail.io", "correct-hash"))
                .assertNext(response -> {
                    assertNotNull(response.token,                    "Token must be non-null");
                    assertEquals("pub-key-25519",    response.publicKey);
                    assertEquals("locked-chest-123", response.encryptedPrivateKey);
                    assertEquals("salt-xyz",          response.passwordSalt);
                })
                .verifyComplete();
    }

    @Test
    void shouldRejectInvalidLogin() {
        UserAccount account = buildTestAccount("marcin@weaponmail.io", "correct-hash");

        when(accountRepository.findById(eq("marcin@weaponmail.io")))
                .thenReturn(Mono.just(account));

        StepVerifier.create(accountService.login("marcin@weaponmail.io", "wrong-hash"))
                .expectErrorMatches(ex ->
                        ex instanceof RuntimeException &&
                        ex.getMessage().contains("Unauthorized"))
                .verify();
    }
 /*
    @Test 
    void shouldRejectSignupForExistingUsername() {
        UserAccount existing = buildTestAccount("taken@weaponmail.io", "hash");

        // Repository says username is already taken
        when(accountRepository.findById(eq("taken@weaponmail.io")))
                .thenReturn(Mono.just(existing));

        UserAccount duplicate = buildTestAccount("taken@weaponmail.io", "other-hash");

        StepVerifier.create(accountService.signUp(duplicate))
                .expectErrorMatches(ex ->
                        ex instanceof IllegalStateException &&
                        ex.getMessage().contains("Username already taken"))
                .verify();
    }
*/
    @Test
    void shouldReturnPublicKeyForKnownUser() {
        UserAccount account = buildTestAccount("marcin@weaponmail.io", "hash");

        when(accountRepository.findById(eq("marcin@weaponmail.io")))
                .thenReturn(Mono.just(account));

        StepVerifier.create(accountService.getPublicKey("marcin@weaponmail.io"))
                .expectNext("pub-key-25519")
                .verifyComplete();
    }

    @Test
    void shouldReturnErrorForUnknownPublicKey() {
        when(accountRepository.findById(eq("ghost@weaponmail.io")))
                .thenReturn(Mono.empty());

        StepVerifier.create(accountService.getPublicKey("ghost@weaponmail.io"))
                .expectErrorMatches(ex ->
                        ex instanceof RuntimeException &&
                        ex.getMessage().contains("User not found"))
                .verify();
    }

    @Test
    void shouldLogoutAndInvalidateSession() {
        UserAccount account = buildTestAccount("marcin@weaponmail.io", "correct-hash");
        when(accountRepository.findById(eq("marcin@weaponmail.io")))
                .thenReturn(Mono.just(account));

        // Login to get a token
        String token = accountService.login("marcin@weaponmail.io", "correct-hash").block().token;
        assertNotNull(token);
        assertEquals("marcin@weaponmail.io", accountService.getUsernameByToken(token));

        // Logout
        accountService.logout(token).block();
        assertNull(accountService.getUsernameByToken(token), "Token must be invalidated after logout");
    }
}