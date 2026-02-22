package com.weaponmail.message;

public record MessageRequest(
        String recipient,
        String subject,
        String encryptedBody,
        String messageKey,
        String senderPublicKey
) {}
