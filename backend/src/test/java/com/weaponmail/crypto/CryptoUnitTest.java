package com.weaponmail.crypto;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Pure unit tests for the cryptographic primitives used by Weapon Mail.
 *
 * No Spring context, no mocks, no database — just raw crypto assertions.
 * These tests verify the correctness and security properties of the individual
 * building blocks: AES-GCM symmetric encryption, HMAC-SHA256 blind tokens,
 * X25519 key serialisation, and ECDH commutativity.
 *
 * Thread-safety note: CryptoTestUtils methods create fresh Cipher / Mac / KeyPair
 * instances on every call, so they are safe to use from concurrent test threads.
 */
class CryptoUnitTest {

    // ─── AES-GCM ─────────────────────────────────────────────────────────────

    @Test
    void aesGcmEncryptDecryptRoundTrip() throws Exception {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        String plaintext = "Weapon Mail AES-GCM round-trip";

        String ciphertext = CryptoTestUtils.encrypt(plaintext, key);
        String decrypted  = CryptoTestUtils.decrypt(ciphertext, key);

        assertEquals(plaintext, decrypted,
                "Decrypted text must match the original plaintext exactly");
    }

    @Test
    void aesGcmProducesDifferentCiphertextsForSamePlaintext() throws Exception {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        String plaintext = "same plaintext";

        String cipher1 = CryptoTestUtils.encrypt(plaintext, key);
        String cipher2 = CryptoTestUtils.encrypt(plaintext, key);

        // Each encryption call uses a fresh random IV, so ciphertexts differ
        assertNotEquals(cipher1, cipher2,
                "AES-GCM must use a fresh IV per encryption — ciphertexts must not be equal");
    }

    @Test
    void aesGcmDecryptionFailsWithWrongKey() {
        byte[] correctKey = new byte[32];
        byte[] wrongKey   = new byte[32];
        new SecureRandom().nextBytes(correctKey);
        new SecureRandom().nextBytes(wrongKey);

        assertThrows(Exception.class, () -> {
            String ciphertext = CryptoTestUtils.encrypt("secret payload", correctKey);
            // Decrypting with the wrong key must fail — AES-GCM authentication tag mismatch
            CryptoTestUtils.decrypt(ciphertext, wrongKey);
        }, "AES-GCM decryption with wrong key must throw due to authentication tag failure");
    }

    // ─── HMAC-SHA256 Blind Tokens ─────────────────────────────────────────────

    @Test
    void hmacSha256BlindTokenIsDeterministic() throws Exception {
        // This mirrors the blind token generation in the frontend CryptoService
        String salt     = "weaponmail-blind-token-salt-v1";
        String senderId = "alice@weaponmail.io";

        byte[] token1 = computeHmac(salt, senderId.toLowerCase());
        byte[] token2 = computeHmac(salt, senderId.toLowerCase());

        assertArrayEquals(token1, token2,
                "HMAC blind token must be deterministic for the same sender ID and salt");
    }

    @Test
    void hmacSha256BlindTokenDiffersForDifferentSenders() throws Exception {
        String salt = "weaponmail-blind-token-salt-v1";

        byte[] tokenAlice = computeHmac(salt, "alice@weaponmail.io");
        byte[] tokenBob   = computeHmac(salt, "bob@weaponmail.io");

        assertFalse(Arrays.equals(tokenAlice, tokenBob),
                "Different senders must produce different blind tokens");
    }

    @Test
    void hmacSha256BlindTokenIsCaseInsensitive() throws Exception {
        String salt = "weaponmail-blind-token-salt-v1";

        byte[] lower  = computeHmac(salt, "Alice@WeaponMail.io".toLowerCase());
        byte[] normal = computeHmac(salt, "alice@weaponmail.io");

        assertArrayEquals(lower, normal,
                "Blind token must be identical regardless of sender email case (after toLowerCase)");
    }

    // ─── X25519 Key Serialisation ─────────────────────────────────────────────

    @Test
    void keySerializationBase64IsLossless() throws Exception {
        AsymmetricCipherKeyPair keyPair = CryptoTestUtils.generateX25519KeyPair();
        X25519PublicKeyParameters original = (X25519PublicKeyParameters) keyPair.getPublic();

        String encoded = CryptoTestUtils.encodePublicKey(original);
        X25519PublicKeyParameters decoded = CryptoTestUtils.decodePublicKey(encoded);

        assertArrayEquals(original.getEncoded(), decoded.getEncoded(),
                "Base64 encode → decode of X25519 public key must be perfectly lossless");
    }

    @Test
    void base64RoundTripPreservesArbitraryBytes() {
        byte[] random = new byte[32];
        new SecureRandom().nextBytes(random);

        String encoded = Base64.getEncoder().encodeToString(random);
        byte[] decoded = Base64.getDecoder().decode(encoded);

        assertArrayEquals(random, decoded,
                "Base64 encode → decode must be an identity transform for arbitrary byte arrays");
    }

    // ─── X25519 ECDH ─────────────────────────────────────────────────────────

    @Test
    void x25519SharedSecretIsCommutative() throws Exception {
        AsymmetricCipherKeyPair alice = CryptoTestUtils.generateX25519KeyPair();
        AsymmetricCipherKeyPair bob   = CryptoTestUtils.generateX25519KeyPair();

        byte[] aliceShared = CryptoTestUtils.calculateSharedSecret(
                (X25519PrivateKeyParameters) alice.getPrivate(),
                (X25519PublicKeyParameters)  bob.getPublic());
        byte[] bobShared   = CryptoTestUtils.calculateSharedSecret(
                (X25519PrivateKeyParameters) bob.getPrivate(),
                (X25519PublicKeyParameters)  alice.getPublic());

        assertArrayEquals(aliceShared, bobShared,
                "ECDH must be commutative: ECDH(alice.priv, bob.pub) == ECDH(bob.priv, alice.pub)");
    }

    @Test
    void x25519DifferentKeyPairsProduceDifferentSecrets() throws Exception {
        AsymmetricCipherKeyPair alice = CryptoTestUtils.generateX25519KeyPair();
        AsymmetricCipherKeyPair bob   = CryptoTestUtils.generateX25519KeyPair();
        AsymmetricCipherKeyPair eve   = CryptoTestUtils.generateX25519KeyPair();

        byte[] aliceBob = CryptoTestUtils.calculateSharedSecret(
                (X25519PrivateKeyParameters) alice.getPrivate(),
                (X25519PublicKeyParameters)  bob.getPublic());
        byte[] aliceEve = CryptoTestUtils.calculateSharedSecret(
                (X25519PrivateKeyParameters) alice.getPrivate(),
                (X25519PublicKeyParameters)  eve.getPublic());

        assertFalse(Arrays.equals(aliceBob, aliceEve),
                "ECDH shared secrets must differ for different key pairs");
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    private static byte[] computeHmac(String keyMaterial, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(keyMaterial.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }
}
