package com.weaponmail.account;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

public class AccountServiceTest {

    private AccountService accountService;

    @BeforeEach
    void setup() {
        accountService = new AccountService();
    }

    @Test
    void shouldRegisterAndLoginUser() {
        // 1. Prepare a 'fake' user account from the browser
        UserAccount account = new UserAccount();
        account.username = "marcin@weaponmail.io";
        account.loginHash = "correct-hash";
        account.publicKey = "pub-key-25519";
        account.encryptedPrivateKey = "locked-chest-123";
        account.passwordSalt = "salt-xyz";

        // 2. Test the SignUp Flow
        Mono<Void> signUpMono = accountService.signUp(account);

        // "Verify that the stream finished without errors"
        StepVerifier.create(signUpMono).verifyComplete();
        Mono<AuthResponse> loginMono = accountService.login("marcin@weaponmail.io", "correct-hash");

        StepVerifier.create(loginMono).assertNext(response -> {
            // "Verify that the 'chest' handed back is the correct one"
            assertNotNull(response.token);
            assertEquals("pub-key-25519", response.publicKey);
            assertEquals("locked-chest-123", response.encryptedPrivateKey);
            assertEquals("salt-xyz", response.passwordSalt);
        }).verifyComplete();
    }

    @Test
    void shouldRejectInvalidLogin() {
        // 1. Register first
        UserAccount account = new UserAccount();
        account.username = "marcin@weaponmail.io";
        account.loginHash = "correct-hash";
        accountService.signUp(account).block(); // Wait for it to finish for this test

        // 2. Attempt login with WRONG hash
        Mono<AuthResponse> loginMono = accountService.login("marcin@weaponmail.io", "wrong-hash");

        StepVerifier.create(loginMono).expectErrorMatches(
                throwable -> throwable instanceof RuntimeException && throwable.getMessage().contains("Unauthorized"))
                .verify();
    }

}
