package com.weaponmail.message;

public record MessageSummary(
        String id,
        String sender,
        String subject,
        long timestamp
) {}
