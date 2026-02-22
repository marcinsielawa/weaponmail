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


public class ConfidenceTest2 {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    @Test
    void testConfidence() throws Exception {
        
        final String originalMessage = "The crow has landed in Stockholm";
        
        X25519KeyPairGenerator generator = new X25519KeyPairGenerator();
        generator.init(new X25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair recipientKeys = generator.generateKeyPair(); 

        // 1. SENDER: Encrypt Body
        byte[] km     = new byte[32]; // Message Key
        byte[] bodyIv = new byte[12];
        new SecureRandom().nextBytes(km);
        new SecureRandom().nextBytes(bodyIv);
        
        Cipher bodyCipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        bodyCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(km, "AES"), new GCMParameterSpec(128, bodyIv));
        byte[] bodyEncrypted = bodyCipher.doFinal(originalMessage.getBytes());
        
        // Bundle Body IV + Ciphertext
        byte[] bodyBundle = new byte[12 + bodyEncrypted.length];
        System.arraycopy(bodyIv, 0, bodyBundle, 0, 12);
        System.arraycopy(bodyEncrypted, 0, bodyBundle, 12, bodyEncrypted.length);

        // 2. SENDER: Wrap Km with ECDH
        AsymmetricCipherKeyPair ephemeral = generator.generateKeyPair();
        X25519Agreement agreement = new X25519Agreement();
        agreement.init(ephemeral.getPrivate());
        byte[] sharedSecret = new byte[32];
        agreement.calculateAgreement(recipientKeys.getPublic(), sharedSecret, 0);

        byte[] wrapIv = new byte[12];
        new SecureRandom().nextBytes(wrapIv);
        Cipher wrapCipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        wrapCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sharedSecret, "AES"), new GCMParameterSpec(128, wrapIv));
        byte[] kmEncrypted = wrapCipher.doFinal(km);

        // Bundle Wrap IV + Ciphertext
        byte[] kmBundle = new byte[12 + kmEncrypted.length];
        System.arraycopy(wrapIv, 0, kmBundle, 0, 12);
        System.arraycopy(kmEncrypted, 0, kmBundle, 12, kmEncrypted.length);

        // 3. RECIPIENT: Unwrap Km
        X25519Agreement recAgreement = new X25519Agreement();
        recAgreement.init(recipientKeys.getPrivate());
        byte[] recSecret = new byte[32];
        recAgreement.calculateAgreement(ephemeral.getPublic(), recSecret, 0);

        byte[] extWrapIv = new byte[12];
        byte[] extWrapCt = new byte[kmBundle.length - 12];
        System.arraycopy(kmBundle, 0, extWrapIv, 0, 12);
        System.arraycopy(kmBundle, 12, extWrapCt, 0, extWrapCt.length);

        Cipher unwrap = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        unwrap.init(Cipher.DECRYPT_MODE, new SecretKeySpec(recSecret, "AES"), new GCMParameterSpec(128, extWrapIv));
        byte[] decryptedKm = unwrap.doFinal(extWrapCt);

        // 4. RECIPIENT: Decrypt Body
        byte[] extBodyIv = new byte[12];
        byte[] extBodyCt = new byte[bodyBundle.length - 12];
        System.arraycopy(bodyBundle, 0, extBodyIv, 0, 12);
        System.arraycopy(bodyBundle, 12, extBodyCt, 0, extBodyCt.length);

        Cipher decrypt = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        decrypt.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decryptedKm, "AES"), new GCMParameterSpec(128, extBodyIv));
        String result = new String(decrypt.doFinal(extBodyCt));

        System.out.println("RESULT: " + result);
        assertEquals(originalMessage, result);
    }
}
