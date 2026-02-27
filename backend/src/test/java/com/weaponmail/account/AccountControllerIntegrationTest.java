package com.weaponmail.account;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import com.weaponmail.message.MessageRepository;

/**
 * HTTP-layer integration tests for AccountController.
 *
 * Uses @SpringBootTest(webEnvironment = RANDOM_PORT) + WebTestClient.
 * Both Cassandra repositories are mocked with @MockitoBean.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class AccountControllerIntegrationTest {

    @Autowired
    private WebTestClient webTestClient;

    @MockitoBean
    private AccountRepository accountRepository;

    @MockitoBean
    private MessageRepository messageRepository;

    // ── Helpers ───────────────────────────────────────────────────────────────

    private UserAccount buildAccount(String username) {
        UserAccount account = new UserAccount();
        account.username           = username;
        account.loginHash          = "sha256-hash-xyz";
        account.publicKey          = "pub-key-25519-base64";
        account.encryptedPrivateKey = "enc-priv-key-base64";
        account.passwordSalt       = "argon2id-salt-base64";
        return account;
    }

    // ── POST /api/account/signup ──────────────────────────────────────────────

    @Test
    void signUp_shouldReturn201() {
        UserAccount account = buildAccount("newuser@weaponmail.io");

        when(accountRepository.findById(eq("newuser@weaponmail.io")))
                .thenReturn(Mono.empty());
        when(accountRepository.save(any(UserAccount.class)))
                .thenReturn(Mono.just(account));

        webTestClient.post()
                .uri("/api/account/signup")
                .bodyValue(account)
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.CREATED);
    }

    // ── POST /api/account/login ───────────────────────────────────────────────

    @Test
    void login_validCredentials_shouldReturnAuthResponse() {
        UserAccount account = buildAccount("marcin@weaponmail.io");

        when(accountRepository.findById(eq("marcin@weaponmail.io")))
                .thenReturn(Mono.just(account));

        LoginRequest login = new LoginRequest();
        login.username = "marcin@weaponmail.io";
        login.loginHash = "sha256-hash-xyz";

        webTestClient.post()
                .uri("/api/account/login")
                .bodyValue(login)
                .exchange()
                .expectStatus().isOk()
                .expectBody(AuthResponse.class)
                .value(response -> {
                    assertNotNull(response.token);
                    assertEquals("pub-key-25519-base64", response.publicKey);
                    assertEquals("enc-priv-key-base64", response.encryptedPrivateKey);
                    assertEquals("argon2id-salt-base64", response.passwordSalt);
                });
    }

    @Test
    void login_invalidCredentials_shouldReturn5xx() {
        UserAccount account = buildAccount("marcin@weaponmail.io");

        when(accountRepository.findById(eq("marcin@weaponmail.io")))
                .thenReturn(Mono.just(account));

        LoginRequest login = new LoginRequest();
        login.username = "marcin@weaponmail.io";
        login.loginHash = "wrong-hash";

        webTestClient.post()
                .uri("/api/account/login")
                .bodyValue(login)
                .exchange()
                .expectStatus().is5xxServerError();
    }

    // ── GET /api/account/{username}/public-key ────────────────────────────────

    @Test
    void getPublicKey_knownUser_shouldReturnKey() {
        UserAccount account = buildAccount("alice@weaponmail.io");

        when(accountRepository.findById(eq("alice@weaponmail.io")))
                .thenReturn(Mono.just(account));

        webTestClient.get()
                .uri("/api/account/{username}/public-key", "alice@weaponmail.io")
                .exchange()
                .expectStatus().isOk()
                .expectBody(PublicKeyResponse.class)
                .value(response -> {
                    assertEquals("alice@weaponmail.io", response.username());
                    assertEquals("pub-key-25519-base64", response.publicKey());
                });
    }

    @Test
    void getPublicKey_unknownUser_shouldReturn5xx() {
        when(accountRepository.findById(eq("ghost@weaponmail.io")))
                .thenReturn(Mono.empty());

        webTestClient.get()
                .uri("/api/account/{username}/public-key", "ghost@weaponmail.io")
                .exchange()
                .expectStatus().is5xxServerError();
    }
}
