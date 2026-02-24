package com.weaponmail.message;

/**
 * Full message detail returned when a user opens a message.
 *
 * encryptedSender — the sender's email address encrypted to the recipient's
 *                   public key (same ECDH shared secret as messageKey wrapping).
 *                   The client decrypts this locally; the server never learns
 *                   who sent the message.
 *
 * senderPublicKey — the ephemeral X25519 public key used by the sender.
 *                   The client needs it to re-derive the ECDH shared secret
 *                   and unwrap both the messageKey and the encryptedSender.
 */
public record MessageDetail(
        String id,
        String threadId,
        String encryptedSender,   // replaces hardcoded "ANONYMOUS" — client decrypts
        String subject,
        String encryptedBody,
        String messageKey,
        String senderPublicKey,
        boolean sealed
) {}