package com.weaponmail.message;

public record MessageSummary(
        String id,
        String threadId,
        String sender,
        String subject,
        long timestamp
) {}
