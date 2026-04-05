package com.weaponmail.message;

/**
 * Inbox summary returned to the client.
 * encryptedSender: The client decrypts this locally to display the sender.
 *                  The server never knows who sent the message.
 */
public record MessageSummary(
        String id,
        String threadId,
        String encryptedSender,  // Client decrypts this — replaces hardcoded "ANONYMOUS"
        String subject,
        long timestamp,
        boolean sealed,
        String senderPublicKey
) {}