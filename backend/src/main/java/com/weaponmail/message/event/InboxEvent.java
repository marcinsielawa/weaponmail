package com.weaponmail.message.event;

/**
 * Lightweight event published to Kafka when a message is stored.
 *
 * <p>The server publishes ONLY what is zero-knowledge safe:
 * - recipient (routing key — already known to the server)
 * - messageId / threadId (opaque UUIDs)
 * - subject (cleartext metadata — already stored as-is)
 * - timestamp
 *
 * The encrypted body, messageKey, and senderPublicKey are NOT in this event.
 * The browser fetches full message detail from REST on demand.
 */
public record InboxEvent(
    String recipient,       // Kafka message key — routes to the right SSE stream
    String messageId,
    String threadId,
    String subject,
    long   timestamp,
    boolean sealed          // Sealed messages still notify (browser decides what to show)
) {}