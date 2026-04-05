package com.weaponmail.crypto;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

/**
 * The cryptographic heart of Weapon Mail. Handles Curve25519 Key Exchange and
 * AES-GCM Authenticated Encryption.
 */
public class CryptoTestUtils {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String AES_ALGO = "AES/GCM/NoPadding";
    private static final int IV_SIZE = 12; // 96-bit IV
    private static final int TAG_SIZE = 128; // 128-bit Authentication Tag

    // --- ASYMMETRIC: Curve25519 (X25519) ---

    public static AsymmetricCipherKeyPair generateX25519KeyPair() {
        X25519KeyPairGenerator generator = new X25519KeyPairGenerator();
        generator.init(new X25519KeyGenerationParameters(new SecureRandom()));
        return generator.generateKeyPair();
    }

    public static byte[] calculateSharedSecret(X25519PrivateKeyParameters privateKey,
            X25519PublicKeyParameters publicKey) {
        X25519Agreement agreement = new X25519Agreement();
        agreement.init(privateKey);
        byte[] secret = new byte[agreement.getAgreementSize()];
        agreement.calculateAgreement(publicKey, secret, 0);
        return secret;
    }

    public static String encodePublicKey(X25519PublicKeyParameters publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    public static X25519PublicKeyParameters decodePublicKey(String base64Key) {
        byte[] bytes = Base64.getDecoder().decode(base64Key);
        return new X25519PublicKeyParameters(bytes, 0);
    }

    // --- SYMMETRIC: AES-256-GCM ---

    public static String encrypt(String plaintext, byte[] key) throws Exception {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance(AES_ALGO, "BC");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_SIZE, iv));

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes());
        byte[] result = new byte[IV_SIZE + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, IV_SIZE);
        System.arraycopy(ciphertext, 0, result, IV_SIZE, ciphertext.length);

        return Base64.getEncoder().encodeToString(result);
    }

    public static String decrypt(String base64Data, byte[] key) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(base64Data);
        byte[] iv = new byte[IV_SIZE];
        byte[] ciphertext = new byte[decoded.length - IV_SIZE];

        System.arraycopy(decoded, 0, iv, 0, IV_SIZE);
        System.arraycopy(decoded, IV_SIZE, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance(AES_ALGO, "BC");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_SIZE, iv));

        return new String(cipher.doFinal(ciphertext));
    }
}