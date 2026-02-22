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

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
public class E2EEncryptionTest {

    @Autowired
    private MessageService service;

    @Test
    void shouldPerformFullE2EEFlow() throws Exception {
        String originalMessage = "The eagle has landed in Stockholm";
        String targetEmail = "marcin@weaponmail.io";

        // 1. RECIPIENT SETUP (User B)
        AsymmetricCipherKeyPair   recipientKeys = CryptoTestUtils.generateX25519KeyPair();
        X25519PublicKeyParameters recipientPub  = (X25519PublicKeyParameters) recipientKeys.getPublic();

        // 2. SENDER ACTION (User A)
        byte[] messageKey = new byte[32];
        new SecureRandom().nextBytes(messageKey);
        String encryptedBody = CryptoTestUtils.encrypt(originalMessage, messageKey);
        AsymmetricCipherKeyPair ephemeral = CryptoTestUtils.generateX25519KeyPair();
        byte[] sharedSecret = CryptoTestUtils.calculateSharedSecret((X25519PrivateKeyParameters) ephemeral.getPrivate(),
                recipientPub);
        String wrappedKey = CryptoTestUtils.encrypt(Base64.getEncoder().encodeToString(messageKey), sharedSecret);

        // 3. SERVER ACTION (Store)
        MessageRequest request = new MessageRequest(targetEmail, "Secret Operation", encryptedBody, wrappedKey,
                CryptoTestUtils.encodePublicKey((X25519PublicKeyParameters) ephemeral.getPublic()));

        // We block here just for the test setup to ensure it's saved
        service.sendMessage(request).block();

        // Give Scylla a millisecond to index
        Thread.sleep(200);

        // 4. RECIPIENT ACTION (The Senior Reactive Chain)
        //  Chain the calls!
        StepVerifier.create(
                service.getMessages(targetEmail).flatMap(summary -> service.getMessageById(targetEmail, summary.id())) 
        ).assertNext(detail -> {
            try {
                // A. Unwrap the Message Key
                X25519PublicKeyParameters senderPub = CryptoTestUtils.decodePublicKey(detail.senderPublicKey());
                byte[] readerSecret = CryptoTestUtils
                        .calculateSharedSecret((X25519PrivateKeyParameters) recipientKeys.getPrivate(), senderPub);

                String decryptedKmBase64 = CryptoTestUtils.decrypt(detail.messageKey(), readerSecret);
                byte[] actualKm = Base64.getDecoder().decode(decryptedKmBase64);

                // B. Decrypt the Body
                String decryptedMessage = CryptoTestUtils.decrypt(detail.encryptedBody(), actualKm);

                assertEquals(originalMessage, decryptedMessage);
                System.out.println("SUCCESS: E2EE Verified. Message: " + decryptedMessage);

            } catch (Exception e) {
                throw new RuntimeException("Decryption logic failed", e);
            }
        }).thenCancel() // This tells the test: "I only care about the first message, ignore the rest"
                .verify();
    }
}