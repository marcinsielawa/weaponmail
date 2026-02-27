package com.weaponmail.message;

import com.datastax.oss.driver.api.core.uuid.Uuids;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import com.weaponmail.account.AccountRepository;

/**
 * HTTP-layer integration tests for MessageController.
 *
 * Uses @SpringBootTest(webEnvironment = RANDOM_PORT) + WebTestClient to exercise
 * all four endpoints against a real embedded Netty server.
 * Cassandra repositories are replaced with @MockitoBean fakes so no live DB is needed.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class MessageControllerIntegrationTest {

    @Autowired
    private WebTestClient webTestClient;

    @MockitoBean
    private MessageRepository messageRepository;

    @MockitoBean
    private AccountRepository accountRepository;

    // ── Helpers ───────────────────────────────────────────────────────────────

    private MessageEntity buildEntity(String recipient, boolean sealed) {
        UUID threadId = UUID.randomUUID();
        MessageKey key = new MessageKey(recipient, threadId, Uuids.timeBased());
        MessageEntity entity = new MessageEntity();
        entity.setKey(key);
        entity.setSubject("Test Subject");
        entity.setEncryptedBody("enc-body-base64");
        entity.setMessageKey("wrapped-key-base64");
        entity.setSenderPublicKey("ephemeral-pub-base64");
        entity.setSenderBlindToken("blind-token-abc");
        entity.setEncryptedSender("enc-sender-base64");
        entity.setSearchTokens(Set.of("token1", "token2"));
        entity.setSealed(sealed);
        return entity;
    }

    private MessageRequest buildRequest(String recipient, boolean sealed) {
        return new MessageRequest(
                recipient,
                null,
                "Test Subject",
                "enc-body-base64",
                "wrapped-key-base64",
                "ephemeral-pub-base64",
                "blind-token-abc",
                "enc-sender-base64",
                Set.of("token1", "token2"),
                sealed
        );
    }

    // ── POST /api/messages ────────────────────────────────────────────────────

    @Test
    void sendMessage_shouldReturn200() {
        MessageEntity entity = buildEntity("alice@weaponmail.io", false);
        when(messageRepository.save(any(MessageEntity.class))).thenReturn(Mono.just(entity));

        webTestClient.post()
                .uri("/api/messages")
                .bodyValue(buildRequest("alice@weaponmail.io", false))
                .exchange()
                .expectStatus().isOk();
    }

    // ── GET /api/messages/{recipient} — inbox listing ─────────────────────────

    @Test
    void getInbox_shouldReturnNonSealedMessages() {
        MessageEntity visible = buildEntity("bob@weaponmail.io", false);
        MessageEntity sealed  = buildEntity("bob@weaponmail.io", true);

        when(messageRepository.findAllByKeyRecipient("bob@weaponmail.io"))
                .thenReturn(Flux.just(visible, sealed));

        webTestClient.get()
                .uri("/api/messages/bob@weaponmail.io")
                .exchange()
                .expectStatus().isOk()
                .expectBodyList(MessageSummary.class)
                .hasSize(1);
    }

    @Test
    void getInbox_sealedMessages_shouldNotAppear() {
        MessageEntity sealed = buildEntity("carol@weaponmail.io", true);

        when(messageRepository.findAllByKeyRecipient("carol@weaponmail.io"))
                .thenReturn(Flux.just(sealed));

        webTestClient.get()
                .uri("/api/messages/carol@weaponmail.io")
                .exchange()
                .expectStatus().isOk()
                .expectBodyList(MessageSummary.class)
                .hasSize(0);
    }

    // ── GET /api/messages/{recipient}/{threadId}/{id} — message detail ─────────

    @Test
    void getMessage_shouldReturnAllFields() {
        MessageEntity entity = buildEntity("dave@weaponmail.io", false);
        String recipient = entity.getKey().recipient();
        String threadId  = entity.getKey().threadId().toString();
        String id        = entity.getKey().id().toString();

        when(messageRepository.findById(any(MessageKey.class))).thenReturn(Mono.just(entity));

        webTestClient.get()
                .uri("/api/messages/{recipient}/{threadId}/{id}", recipient, threadId, id)
                .exchange()
                .expectStatus().isOk()
                .expectBody(MessageDetail.class)
                .value(detail -> {
                    assertEquals("Test Subject", detail.subject());
                    assertEquals("enc-body-base64", detail.encryptedBody());
                    assertEquals("wrapped-key-base64", detail.messageKey());
                    assertEquals("ephemeral-pub-base64", detail.senderPublicKey());
                });
    }

    @Test
    void getMessage_sealed_shouldBeAccessibleByDirectId() {
        MessageEntity entity = buildEntity("eve@weaponmail.io", true);
        String recipient = entity.getKey().recipient();
        String threadId  = entity.getKey().threadId().toString();
        String id        = entity.getKey().id().toString();

        when(messageRepository.findById(any(MessageKey.class))).thenReturn(Mono.just(entity));

        webTestClient.get()
                .uri("/api/messages/{recipient}/{threadId}/{id}", recipient, threadId, id)
                .exchange()
                .expectStatus().isOk()
                .expectBody(MessageDetail.class)
                .value(detail -> {
                    assertTrue(detail.sealed());
                    assertEquals("Test Subject", detail.subject());
                });
    }

    // ── GET /api/messages/{recipient}/search/{token} — blind token search ──────

    @Test
    void searchBySender_shouldReturnMatchingNonSealedMessages() {
        MessageEntity entity = buildEntity("frank@weaponmail.io", false);

        when(messageRepository.findAllByKeyRecipientAndSenderBlindToken(
                eq("frank@weaponmail.io"), eq("blind-token-abc")))
                .thenReturn(Flux.just(entity));

        webTestClient.get()
                .uri("/api/messages/{recipient}/search/{token}",
                        "frank@weaponmail.io", "blind-token-abc")
                .exchange()
                .expectStatus().isOk()
                .expectBodyList(MessageSummary.class)
                .hasSize(1);
    }

    @Test
    void searchBySender_sealed_shouldNotAppear() {
        MessageEntity sealed = buildEntity("grace@weaponmail.io", true);

        when(messageRepository.findAllByKeyRecipientAndSenderBlindToken(
                eq("grace@weaponmail.io"), eq("blind-token-xyz")))
                .thenReturn(Flux.just(sealed));

        webTestClient.get()
                .uri("/api/messages/{recipient}/search/{token}",
                        "grace@weaponmail.io", "blind-token-xyz")
                .exchange()
                .expectStatus().isOk()
                .expectBodyList(MessageSummary.class)
                .hasSize(0);
    }
}
