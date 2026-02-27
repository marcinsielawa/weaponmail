package com.weaponmail.message;

import com.datastax.oss.driver.api.core.uuid.Uuids;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.CassandraContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import reactor.test.StepVerifier;

import java.util.Set;
import java.util.UUID;

import com.weaponmail.account.AccountRepository;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/**
 * Repository integration tests using Testcontainers to spin up a real
 * Cassandra (ScyllaDB-compatible) container.
 *
 * These tests verify the full persistence layer without any mocking:
 * - Save a MessageEntity and read it back
 * - findAllByKeyRecipient returns correct results
 * - findAllByKeyRecipientAndSenderBlindToken filters correctly
 * - Sealed messages are stored and retrievable by direct ID lookup
 *
 * Disabled in environments where Docker is unavailable (CI flag SKIP_DB_TESTS).
 */
@SpringBootTest
@Testcontainers
@DisabledIfEnvironmentVariable(named = "SKIP_DB_TESTS", matches = "true")
class MessageRepositoryIntegrationTest {

    @SuppressWarnings("resource")
    @Container
    static CassandraContainer<?> cassandra =
            new CassandraContainer<>("cassandra:4.1")
                    .withInitScript("schema.cql");

    @MockitoBean
    private AccountRepository accountRepository;

    @DynamicPropertySource
    static void cassandraProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.cassandra.contact-points",
                () -> cassandra.getHost() + ":" + cassandra.getMappedPort(9042));
        registry.add("spring.cassandra.local-datacenter", () -> "datacenter1");
        registry.add("spring.cassandra.keyspace-name",    () -> "weaponmail");
        registry.add("spring.cassandra.schema-action",    () -> "create_if_not_exists");
    }

    @Autowired
    private MessageRepository messageRepository;

    // ── Helpers ───────────────────────────────────────────────────────────────

    private MessageEntity buildEntity(String recipient, String blindToken, boolean sealed) {
        UUID threadId = UUID.randomUUID();
        MessageKey key = new MessageKey(recipient, threadId, Uuids.timeBased());
        MessageEntity entity = new MessageEntity();
        entity.setKey(key);
        entity.setSubject("Integration Test Message");
        entity.setEncryptedBody("enc-body-base64");
        entity.setMessageKey("wrapped-key-base64");
        entity.setSenderPublicKey("ephemeral-pub-base64");
        entity.setSenderBlindToken(blindToken);
        entity.setEncryptedSender("enc-sender-base64");
        entity.setSearchTokens(Set.of("token-a", "token-b"));
        entity.setSealed(sealed);
        return entity;
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    @Test
    void saveAndFindById_shouldRoundTrip() {
        MessageEntity entity = buildEntity("it-user1@weaponmail.io", "blind-token-1", false);
        messageRepository.save(entity).block();

        StepVerifier.create(messageRepository.findById(entity.getKey()))
                .assertNext(found -> {
                    assert found.getSubject().equals("Integration Test Message");
                    assert found.getEncryptedBody().equals("enc-body-base64");
                    assert found.getSenderBlindToken().equals("blind-token-1");
                    assert !found.isSealed();
                })
                .verifyComplete();
    }

    @Test
    void findAllByKeyRecipient_shouldReturnAllMessages() {
        String recipient = "it-user2@weaponmail.io";
        MessageEntity msg1 = buildEntity(recipient, "token-x", false);
        MessageEntity msg2 = buildEntity(recipient, "token-y", false);
        messageRepository.save(msg1).block();
        messageRepository.save(msg2).block();

        StepVerifier.create(messageRepository.findAllByKeyRecipient(recipient))
                .expectNextCount(2)
                .verifyComplete();
    }

    @Test
    void findAllByKeyRecipientAndSenderBlindToken_shouldFilterCorrectly() {
        String recipient = "it-user3@weaponmail.io";
        MessageEntity fromSenderA = buildEntity(recipient, "sender-a-token", false);
        MessageEntity fromSenderB = buildEntity(recipient, "sender-b-token", false);
        messageRepository.save(fromSenderA).block();
        messageRepository.save(fromSenderB).block();

        StepVerifier.create(
                messageRepository.findAllByKeyRecipientAndSenderBlindToken(recipient, "sender-a-token"))
                .assertNext(found -> assert found.getSenderBlindToken().equals("sender-a-token"))
                .verifyComplete();
    }

    @Test
    void sealedMessage_shouldBeRetrievableByDirectId() {
        String recipient = "it-user4@weaponmail.io";
        MessageEntity sealed = buildEntity(recipient, "blind-token-sealed", true);
        messageRepository.save(sealed).block();

        StepVerifier.create(messageRepository.findById(sealed.getKey()))
                .assertNext(found -> {
                    assert found.isSealed();
                    assert found.getSubject().equals("Integration Test Message");
                })
                .verifyComplete();
    }
}
