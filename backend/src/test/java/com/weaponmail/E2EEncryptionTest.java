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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import reactor.test.StepVerifier;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

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

        // ── 1. RECIPIENT SETUP ───────────────────────────────────────��─────────
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
        // Construct MessageRequest with the FULL updated signature (10 fields).
        MessageRequest request = new MessageRequest(
                targetEmail,
                null,                           // threadId — null for new thread
                "Secret Operation",             // subject (cleartext metadata)
                encryptedBody,
                wrappedKey,
                ephemeralPublicKeyBase64,
                "BLIND-HASH-TOKEN-XYZ",         // senderBlindToken
                "ENCRYPTED-SENDER-PLACEHOLDER", // encryptedSender (not exercised here)
                Set.of(),                       // searchTokens (empty for this test)
                false,                          // sealed
                java.util.List.of()             // attachments (empty for this test)
        );

        // Build the entity that the mock repository will return on read-back.
        // This simulates a Cassandra round-trip without touching a real DB.
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
}