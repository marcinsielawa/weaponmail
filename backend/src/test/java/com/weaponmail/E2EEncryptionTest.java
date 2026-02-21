package com.weaponmail;

import com.weaponmail.crypto.CryptoTestUtils;
import com.weaponmail.message.MessageRequest;
import com.weaponmail.message.MessageService;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import java.security.SecureRandom;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class E2EEncryptionTest {

    @Test
    void shouldPerformFullE2EEFlow() throws Exception {
        MessageService service = new MessageService();
        String originalMessage = "The eagle has landed in Stockholm";

        // 1. RECIPIENT SETUP (User B)
        AsymmetricCipherKeyPair   recipientKeys = CryptoTestUtils.generateX25519KeyPair();
        X25519PublicKeyParameters recipientPub  = (X25519PublicKeyParameters) recipientKeys.getPublic();

        // 2. SENDER ACTION (User A)
        // A. Generate random 256-bit Message Key (Km)
        byte[] messageKey = new byte[32];
        new SecureRandom().nextBytes(messageKey);

        // B. Encrypt Body with Km
        String encryptedBody = CryptoTestUtils.encrypt(originalMessage, messageKey);

        // C. Wrap Km using ECDH (Ephemeral Handshake)
        AsymmetricCipherKeyPair ephemeral = CryptoTestUtils.generateX25519KeyPair();
        byte[] sharedSecret = CryptoTestUtils.calculateSharedSecret((X25519PrivateKeyParameters) ephemeral.getPrivate(),
                recipientPub);

        String wrappedKey = CryptoTestUtils.encrypt(Base64.getEncoder().encodeToString(messageKey), sharedSecret);

        // 3. SERVER ACTION (Store the data)
        MessageRequest request = new MessageRequest();
        request.recipient = "marcin@weaponmail.io";
        request.encryptedBody = encryptedBody;
        request.messageKey = wrappedKey;
        request.senderPublicKey = CryptoTestUtils.encodePublicKey((X25519PublicKeyParameters) ephemeral.getPublic());

        StepVerifier.create(service.sendMessage(request)).verifyComplete();

        // 4. RECIPIENT ACTION (Read and Decrypt)
        StepVerifier.create(service.getMessages("INBOX")).assertNext(summary -> {
            service.getMessageById(summary.id).subscribe(detail -> {
                try {
                    // A. Unwrap the Message Key
                    X25519PublicKeyParameters senderPub = CryptoTestUtils.decodePublicKey(detail.senderPublicKey);
                    byte[] readerSecret = CryptoTestUtils
                            .calculateSharedSecret((X25519PrivateKeyParameters) recipientKeys.getPrivate(), senderPub);

                    String decryptedKmBase64 = CryptoTestUtils.decrypt(detail.messageKey, readerSecret);
                    byte[] actualKm = Base64.getDecoder().decode(decryptedKmBase64);

                    // B. Decrypt the Body
                    String decryptedMessage = CryptoTestUtils.decrypt(detail.encryptedBody, actualKm);

                    assertEquals(originalMessage, decryptedMessage);
                    System.out.println("SUCCESS: E2EE Verified. Message: " + decryptedMessage);

                } catch (Exception e) {
                    throw new RuntimeException("Decryption logic failed", e);
                }
            });
        }).verifyComplete();
    }
}