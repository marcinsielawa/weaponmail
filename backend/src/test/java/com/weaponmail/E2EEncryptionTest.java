package com.weaponmail;

import com.weaponmail.crypto.CryptoTestUtils;
import com.weaponmail.message.MessageRequest;
import com.weaponmail.message.MessageService;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import reactor.test.StepVerifier;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
public class E2EEncryptionTest {

    @Autowired
    private MessageService service;

    @Test
    void shouldPerformFullE2EEFlow() throws Exception {
        String originalMessage = "The eagle has landed in Stockholm";
        String targetEmail = "marcin@weaponmail.io";

        // 1. RECIPIENT SETUP
        AsymmetricCipherKeyPair recipientKeys = CryptoTestUtils.generateX25519KeyPair();
        X25519PublicKeyParameters recipientPub = (X25519PublicKeyParameters) recipientKeys.getPublic();

        // 2. SENDER ACTION
        byte[] messageKey = new byte[32];
        new SecureRandom().nextBytes(messageKey);
        String encryptedBody = CryptoTestUtils.encrypt(originalMessage, messageKey);
        AsymmetricCipherKeyPair ephemeral = CryptoTestUtils.generateX25519KeyPair();
        byte[] sharedSecret = CryptoTestUtils.calculateSharedSecret((X25519PrivateKeyParameters) ephemeral.getPrivate(), recipientPub);
        String wrappedKey = CryptoTestUtils.encrypt(Base64.getEncoder().encodeToString(messageKey), sharedSecret);

        // 3. SERVER ACTION (Store with Threading and Blind Token)
        MessageRequest request = new MessageRequest(
            targetEmail, 
            null, // New Thread
            "Secret Operation", 
            encryptedBody, 
            wrappedKey,
            CryptoTestUtils.encodePublicKey((X25519PublicKeyParameters) ephemeral.getPublic()),
            "BLIND-HASH-TOKEN-XYZ" // New Blind Token
        );

        service.sendMessage(request).block();
        Thread.sleep(200); // Wait for indexing

        // 4. RECIPIENT ACTION (The Senior Reactive Chain)
        StepVerifier.create(
            service.getMessages(targetEmail)
                   .flatMap(summary -> service.getMessageById(targetEmail, summary.threadId(), summary.id())) 
        ).assertNext(detail -> {
            try {
                // Decrypt the Message Key using Recipient's Private Key + Sender's Public Key
                X25519PublicKeyParameters senderPub = CryptoTestUtils.decodePublicKey(detail.senderPublicKey());
                byte[] readerSecret = CryptoTestUtils.calculateSharedSecret((X25519PrivateKeyParameters) recipientKeys.getPrivate(), senderPub);

                String decryptedKmBase64 = CryptoTestUtils.decrypt(detail.messageKey(), readerSecret);
                byte[] actualKm = Base64.getDecoder().decode(decryptedKmBase64);

                // Decrypt the Body
                String decryptedMessage = CryptoTestUtils.decrypt(detail.encryptedBody(), actualKm);

                assertEquals(originalMessage, decryptedMessage);
                System.out.println("SUCCESS: E2EE Verified. Message: " + decryptedMessage);

            } catch (Exception e) {
                throw new RuntimeException("Decryption logic failed", e);
            }
        }).thenCancel().verify();
    }
}