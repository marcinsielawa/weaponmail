package com.weaponmail;


import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.junit.jupiter.api.Test;

import com.weaponmail.message.MessageRequest;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class ConfidenceTest3 {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    @Test
    void testConfidence() throws Exception {
        
        // given 
        
        final String originalMessage = "The crow has landed in Stockholm";
        final String recipient       = "foobar@blabermouuse.org";
        final String subject         = "A confidential matter"; 
        
        X25519KeyPairGenerator generator = new X25519KeyPairGenerator();
        generator.init(new X25519KeyGenerationParameters(new SecureRandom()));
        
        AsymmetricCipherKeyPair recipientKeyPair = generator.generateKeyPair(); 
       
        byte[] messageSpecificKeyBytes = new byte[32];
        new SecureRandom().nextBytes(messageSpecificKeyBytes);
        
        byte[] messageIv = new byte[12];
        new SecureRandom().nextBytes(messageIv);
        Cipher aesForMessage = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        aesForMessage.init(Cipher.ENCRYPT_MODE, 
                new SecretKeySpec(messageSpecificKeyBytes, "AES"), 
                new GCMParameterSpec(128, messageIv));
        
        byte[] encryptedMessageBytes = aesForMessage.doFinal(originalMessage.getBytes());
        
        byte[] messageIvAndCipherText = new byte[messageIv.length + encryptedMessageBytes.length];
        
        System.arraycopy(messageIv            , 0, messageIvAndCipherText, 0, 12);
        System.arraycopy(encryptedMessageBytes, 0, messageIvAndCipherText, 12, encryptedMessageBytes.length);

        // ecliptic curve diffie helman
        
        X25519KeyPairGenerator ecdhGenerator = new X25519KeyPairGenerator();
        ecdhGenerator.init(new X25519KeyGenerationParameters(new SecureRandom()));
        
        AsymmetricCipherKeyPair ephemeral = ecdhGenerator.generateKeyPair();
        
        X25519Agreement senderAgreement = new X25519Agreement();
        byte[] senderSharedSecret = new byte[senderAgreement.getAgreementSize()];
        senderAgreement.init(ephemeral.getPrivate());
        senderAgreement.calculateAgreement(recipientKeyPair.getPublic(), senderSharedSecret, 0);

        byte[] ecdhIv = new byte[12];
        new SecureRandom().nextBytes(ecdhIv);
        Cipher ecdhAes = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        ecdhAes.init(Cipher.ENCRYPT_MODE, 
                new SecretKeySpec(senderSharedSecret, "AES"), 
                new GCMParameterSpec(128, ecdhIv));
        byte[] encryptedMessageSpecificKeyBytes = ecdhAes.doFinal(messageSpecificKeyBytes);

        byte[] ecdhIvAndEncryptedMessageSpecificKeyBytes = new byte[ecdhIv.length + encryptedMessageSpecificKeyBytes.length];
        
        System.arraycopy(ecdhIv, 0, ecdhIvAndEncryptedMessageSpecificKeyBytes, 0, ecdhIv.length);
        System.arraycopy(encryptedMessageSpecificKeyBytes, 0, ecdhIvAndEncryptedMessageSpecificKeyBytes, ecdhIv.length, encryptedMessageSpecificKeyBytes.length);
        
        // when
        
        MessageRequest request = new MessageRequest(
                recipient,
                subject  ,
                Base64.getEncoder().encodeToString(messageIvAndCipherText),
                Base64.getEncoder().encodeToString(ecdhIvAndEncryptedMessageSpecificKeyBytes),
                Base64.getEncoder().encodeToString(((X25519PublicKeyParameters) ephemeral.getPublic()).getEncoded())
        );
        
        // then

        X25519Agreement receiverAgreement = new X25519Agreement();
        byte[] receiverSharedSecret = new byte[receiverAgreement.getAgreementSize()];
        receiverAgreement.init(recipientKeyPair.getPrivate());
        receiverAgreement.calculateAgreement(ephemeral.getPublic(), receiverSharedSecret, 0);

        byte[] receiverSharedSecretIv     = new byte[12];
        byte[] receiverSharedSecretAesKey = new byte[ecdhIvAndEncryptedMessageSpecificKeyBytes.length - 12];
        
        System.arraycopy(ecdhIvAndEncryptedMessageSpecificKeyBytes, 0 , receiverSharedSecretIv    , 0, 12);
        System.arraycopy(ecdhIvAndEncryptedMessageSpecificKeyBytes, 12, receiverSharedSecretAesKey, 0, receiverSharedSecretAesKey.length);

        Cipher unwrapAes = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        unwrapAes.init(Cipher.DECRYPT_MODE, 
                new SecretKeySpec(receiverSharedSecret, "AES"), 
                new GCMParameterSpec(128, receiverSharedSecretIv));
        
        byte[] decryptedKm = unwrapAes.doFinal(receiverSharedSecretAesKey);

        // 4. RECIPIENT: Decrypt Body
        byte[] extBodyIv = new byte[12];
        byte[] extBodyCt = new byte[messageIvAndCipherText.length - 12];
        System.arraycopy(messageIvAndCipherText, 0, extBodyIv, 0, 12);
        System.arraycopy(messageIvAndCipherText, 12, extBodyCt, 0, extBodyCt.length);

        Cipher decrypt = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        decrypt.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decryptedKm, "AES"), new GCMParameterSpec(128, extBodyIv));
        String result = new String(decrypt.doFinal(extBodyCt));

        System.out.println("RESULT: " + result);
        assertEquals(originalMessage, result);
    }
}
