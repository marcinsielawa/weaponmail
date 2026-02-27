package com.weaponmail;

import com.weaponmail.crypto.CryptoTestUtils;
import com.weaponmail.message.MessageRequest;
import com.weaponmail.message.MessageService;
import com.weaponmail.message.MessageRepository;
import com.weaponmail.account.AccountRepository;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import reactor.test.StepVerifier;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.weaponmail.message.MessageEntity;
import com.weaponmail.message.MessageKey;
import com.datastax.oss.driver.api.core.uuid.Uuids;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

/**
 * End-to-End Encryption Integration Test.
 *
 * Verifies the full cryptographic handshake without requiring a live ScyllaDB.
 * Uses @MockitoBean (Spring Boot 3.4+) to replace Cassandra repositories with
 * controlled in-memory fakes, so the test is hermetic and always green.
 *
 * Crypto flow tested:
 *   Sender: ECDH(ephemeral.priv, recipient.pub) → sharedSecret → AES-GCM(messageKey)
 *   Recipient: ECDH(recipient.priv, ephemeral.pub) → same sharedSecret → AES-GCM⁻¹(messageKey)
 */
@SpringBootTest
@ActiveProfiles("test")
@ContextConfiguration(initializers = CassandraContainerInitializer.class)
public class E2EEncryptionTest {

    @Autowired
    private MessageService service;

    // Mock out both Cassandra repositories so this test runs without a live DB.
    // The crypto logic is what we are verifying here — not DB connectivity.
    @MockitoBean
    private MessageRepository messageRepository;

    @MockitoBean
    private AccountRepository accountRepository;

    @Test
    void shouldPerformFullE2EEFlow() throws Exception {
        final String originalMessage = "The eagle has landed in Stockholm";
        final String targetEmail     = "marcin@weaponmail.io";
        final UUID   threadId        = UUID.randomUUID();

        // ── 1. RECIPIENT SETUP ─────────────────────────────────────────────────
        AsymmetricCipherKeyPair recipientKeys = CryptoTestUtils.generateX25519KeyPair();
        X25519PublicKeyParameters  recipientPub  = (X25519PublicKeyParameters)  recipientKeys.getPublic();
        X25519PrivateKeyParameters recipientPriv = (X25519PrivateKeyParameters) recipientKeys.getPrivate();

        // ── 2. SENDER: Encrypt ─────────────────────────────────────────────────
        // Generate a random 32-byte AES body key
        byte[] messageKey = new byte[32];
        new SecureRandom().nextBytes(messageKey);

        // Encrypt the body with the AES key
        String encryptedBody = CryptoTestUtils.encrypt(originalMessage, messageKey);

        // Generate an ephemeral X25519 keypair (perfect forward secrecy)
        AsymmetricCipherKeyPair ephemeral    = CryptoTestUtils.generateX25519KeyPair();
        X25519PublicKeyParameters  ephPub    = (X25519PublicKeyParameters)  ephemeral.getPublic();
        X25519PrivateKeyParameters ephPriv   = (X25519PrivateKeyParameters) ephemeral.getPrivate();

        // ECDH: derive shared secret using ephemeral private + recipient public
        byte[] sharedSecret = CryptoTestUtils.calculateSharedSecret(ephPriv, recipientPub);

        // Wrap (encrypt) the AES message key with the shared secret
        // We Base64-encode the raw key bytes before encrypting so decrypt → Base64.decode works.
        String wrappedKey = CryptoTestUtils.encrypt(
                Base64.getEncoder().encodeToString(messageKey), sharedSecret);

        String ephemeralPublicKeyBase64 = CryptoTestUtils.encodePublicKey(ephPub);

        // ── 3. SERVER: Build and "store" the message ───────────────────────────
        // Construct MessageRequest with the FULL updated signature (11 fields).
        MessageRequest request = new MessageRequest(
                targetEmail,
                null,                           // threadId — null for new thread
                "Secret Operation",             // subject (cleartext metadata)
                encryptedBody,
                wrappedKey,
                ephemeralPublicKeyBase64,
                "BLIND-HASH-TOKEN-XYZ",         // senderBlindToken
                "ENCRYPTED-SENDER-PLACEHOLDER", // encryptedSender
                Set.of(),                       // searchTokens
                false,                          // sealed
                java.util.List.of()             // attachments (NEW)
        );

        // Build the entity that the mock repository will return on read-back.
        MessageKey key = new MessageKey(targetEmail, threadId, Uuids.timeBased());
        MessageEntity storedEntity = new MessageEntity();
        storedEntity.setKey(key);
        storedEntity.setSubject(request.subject());
        storedEntity.setEncryptedBody(request.encryptedBody());
        storedEntity.setMessageKey(request.messageKey());
        storedEntity.setSenderPublicKey(request.senderPublicKey());
        storedEntity.setSenderBlindToken(request.senderBlindToken());
        storedEntity.setEncryptedSender(request.encryptedSender());
        storedEntity.setSearchTokens(request.searchTokens());
        storedEntity.setSealed(request.sealed());
        storedEntity.setAttachments(request.attachments()); // Keep entity in sync

        // Wire mock: save returns the entity, findAll returns it, findById returns it.
        when(messageRepository.save(any(MessageEntity.class))).thenReturn(Mono.just(storedEntity));
        when(messageRepository.findAllByKeyRecipient(targetEmail)).thenReturn(Flux.just(storedEntity));
        when(messageRepository.findById(any(MessageKey.class))).thenReturn(Mono.just(storedEntity));

        // Trigger the send (saves through mock)
        service.sendMessage(request).block();

        // ── 4. RECIPIENT: Fetch → Decrypt ──────────────────────────────────────
        StepVerifier.create(
            service.getMessages(targetEmail)
                   .flatMap(summary -> service.getMessageById(
                           targetEmail,
                           summary.threadId(),
                           summary.id()))
        ).assertNext(detail -> {
            try {
                // Re-derive the shared secret from the recipient's side:
                //   ECDH(recipient.priv, ephemeral.pub) == ECDH(ephemeral.priv, recipient.pub) ✓
                X25519PublicKeyParameters senderEphemeralPub =
                        CryptoTestUtils.decodePublicKey(detail.senderPublicKey());
                byte[] readerSecret =
                        CryptoTestUtils.calculateSharedSecret(recipientPriv, senderEphemeralPub);

                // Unwrap the AES message key
                String decryptedKmBase64 = CryptoTestUtils.decrypt(detail.messageKey(), readerSecret);
                byte[] actualMessageKey  = Base64.getDecoder().decode(decryptedKmBase64);

                // Decrypt the body
                String decryptedMessage = CryptoTestUtils.decrypt(detail.encryptedBody(), actualMessageKey);

                assertEquals(originalMessage, decryptedMessage,
                        "Decrypted message must exactly match the original plaintext");

                System.out.println("✅ E2EE Verified. Decrypted: " + decryptedMessage);

            } catch (Exception e) {
                throw new RuntimeException("Decryption pipeline failed", e);
            }
        }).verifyComplete();
    }

    /**
     * Negative test: Decryption MUST fail when using the wrong private key.
     *
     * AES-GCM is authenticated encryption — decrypting a ciphertext with a different
     * shared secret produces an authentication tag mismatch, which throws an exception.
     * This verifies that the crypto primitives enforce integrity.
     */
    @Test
    void shouldFailDecryptionWithWrongPrivateKey() throws Exception {
        // Real recipient key pair
        AsymmetricCipherKeyPair realRecipient = CryptoTestUtils.generateX25519KeyPair();
        X25519PublicKeyParameters realPub     = (X25519PublicKeyParameters) realRecipient.getPublic();

        // Attacker's key pair (different identity — does NOT match the ciphertext)
        AsymmetricCipherKeyPair wrongRecipient = CryptoTestUtils.generateX25519KeyPair();
        X25519PrivateKeyParameters wrongPriv   = (X25519PrivateKeyParameters) wrongRecipient.getPrivate();

        // Sender generates an ephemeral keypair and encrypts for the REAL recipient
        byte[] messageKey = new byte[32];
        new SecureRandom().nextBytes(messageKey);
        AsymmetricCipherKeyPair ephemeral    = CryptoTestUtils.generateX25519KeyPair();
        X25519PublicKeyParameters  ephPub    = (X25519PublicKeyParameters) ephemeral.getPublic();
        X25519PrivateKeyParameters ephPriv   = (X25519PrivateKeyParameters) ephemeral.getPrivate();

        byte[] correctSecret = CryptoTestUtils.calculateSharedSecret(ephPriv, realPub);
        String wrappedKey    = CryptoTestUtils.encrypt(
                Base64.getEncoder().encodeToString(messageKey), correctSecret);

        // Attacker tries to decrypt the wrapped key using a WRONG shared secret
        X25519PublicKeyParameters ephPubDecoded =
                CryptoTestUtils.decodePublicKey(CryptoTestUtils.encodePublicKey(ephPub));
        byte[] wrongSecret = CryptoTestUtils.calculateSharedSecret(wrongPriv, ephPubDecoded);

        assertThrows(Exception.class,
                () -> CryptoTestUtils.decrypt(wrappedKey, wrongSecret),
                "AES-GCM decryption with wrong private key must throw an authentication error");
    }

    /**
     * Sealed messages MUST NOT appear in the general inbox listing.
     *
     * MessageService.getMessages() applies a .filter(entity -> !entity.isSealed()) so that
     * sealed messages are only retrievable via direct getMessageById() lookup.
     */
    @Test
    void shouldExcludeSealedMessagesFromInboxListing() {
        final String recipient = "vault@weaponmail.io";

        MessageKey key = new MessageKey(recipient, UUID.randomUUID(), Uuids.timeBased());
        MessageEntity sealedEntity = new MessageEntity();
        sealedEntity.setKey(key);
        sealedEntity.setSubject("Sealed Secret");
        sealedEntity.setSealed(true);
        sealedEntity.setEncryptedBody("encrypted-body");
        sealedEntity.setMessageKey("wrapped-key");
        sealedEntity.setSenderPublicKey("pub-key");
        sealedEntity.setSenderBlindToken("blind-token");
        sealedEntity.setEncryptedSender("encrypted-sender");
        sealedEntity.setSearchTokens(Set.of());

        when(messageRepository.findAllByKeyRecipient(recipient))
                .thenReturn(Flux.just(sealedEntity));

        // getMessages must filter out sealed messages — inbox should be empty
        StepVerifier.create(service.getMessages(recipient))
                .expectNextCount(0)
                .verifyComplete();
    }

    /**
     * Zero-knowledge sender search: searchBySender matches on the HMAC blind token
     * and returns the matching message summary, excluding sealed messages.
     */
    @Test
    void shouldFindNonSealedMessageBySenderBlindToken() {
        final String recipient  = "inbox@weaponmail.io";
        final String blindToken = "HMAC-SHA256-BLIND-TOKEN-ABC";

        MessageKey key = new MessageKey(recipient, UUID.randomUUID(), Uuids.timeBased());
        MessageEntity entity = new MessageEntity();
        entity.setKey(key);
        entity.setSubject("Zk Search Hit");
        entity.setSealed(false);
        entity.setEncryptedBody("encrypted-body");
        entity.setMessageKey("wrapped-key");
        entity.setSenderPublicKey("pub-key");
        entity.setSenderBlindToken(blindToken);
        entity.setEncryptedSender("encrypted-sender");
        entity.setSearchTokens(Set.of());

        when(messageRepository.findAllByKeyRecipientAndSenderBlindToken(recipient, blindToken))
                .thenReturn(Flux.just(entity));

        StepVerifier.create(service.searchBySender(recipient, blindToken))
                .assertNext(summary -> {
                    assertEquals("Zk Search Hit", summary.subject(),
                            "Subject must match the stored message");
                    assertFalse(summary.sealed(), "Non-sealed message must appear in blind search results");
                })
                .verifyComplete();
    }

    /**
     * Sealed messages MUST be excluded from the blind token sender search.
     * searchBySender applies the same sealed filter as getMessages.
     */
    @Test
    void shouldExcludeSealedMessageFromBlindTokenSearch() {
        final String recipient  = "inbox@weaponmail.io";
        final String blindToken = "HMAC-SHA256-BLIND-TOKEN-XYZ";

        MessageKey key = new MessageKey(recipient, UUID.randomUUID(), Uuids.timeBased());
        MessageEntity sealedEntity = new MessageEntity();
        sealedEntity.setKey(key);
        sealedEntity.setSubject("Hidden");
        sealedEntity.setSealed(true);
        sealedEntity.setEncryptedBody("encrypted-body");
        sealedEntity.setMessageKey("wrapped-key");
        sealedEntity.setSenderPublicKey("pub-key");
        sealedEntity.setSenderBlindToken(blindToken);
        sealedEntity.setEncryptedSender("encrypted-sender");
        sealedEntity.setSearchTokens(Set.of());

        when(messageRepository.findAllByKeyRecipientAndSenderBlindToken(recipient, blindToken))
                .thenReturn(Flux.just(sealedEntity));

        StepVerifier.create(service.searchBySender(recipient, blindToken))
                .expectNextCount(0)
                .verifyComplete();
    }

    /**
     * Verifies that searchTokens are persisted on the stored entity during sendMessage.
     *
     * The server stores HMAC-SHA256 keyword tokens as opaque blobs for blind search.
     * This test ensures they survive the service layer unmodified.
     */
    @Test
    void shouldPersistSearchTokensWithMessage() {
        final String recipient = "search@weaponmail.io";
        final Set<String> searchTokens = Set.of("TOKEN-ALPHA", "TOKEN-BETA");

        // Updated constructor with 11 arguments (added empty attachments list)
        MessageRequest request = new MessageRequest(
                recipient,
                null,                           // threadId
                "Keyword Search Test",          // subject
                "encrypted-body",               // encryptedBody
                "wrapped-key",                  // messageKey
                "ephemeral-pub-key",            // senderPublicKey
                "blind-token",                  // senderBlindToken
                "encrypted-sender",             // encryptedSender
                searchTokens,                   // searchTokens
                false,                          // sealed
                java.util.List.of()             // attachments (NEW)
        );

        // Capture the entity actually passed to repository.save(...)
        org.mockito.ArgumentCaptor<MessageEntity> captor = org.mockito.ArgumentCaptor.forClass(MessageEntity.class);
        when(messageRepository.save(captor.capture())).thenReturn(
                Mono.just(new MessageEntity())
        );

        service.sendMessage(request).block();

        MessageEntity saved = captor.getValue();
        assertEquals(searchTokens, saved.getSearchTokens(),
                "Search tokens must be persisted exactly as provided by the client");
    }
}