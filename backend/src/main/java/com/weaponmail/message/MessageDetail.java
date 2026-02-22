package com.weaponmail.message;

public record MessageDetail(
        String id,
        String sender,
        String subject,
        String encryptedBody,
        String messageKey,
        String senderPublicKey
) {}
