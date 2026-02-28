package com.weaponmail.message;

import java.util.List;
import java.util.Set;

/**
 * The "Encrypted Envelope" DTO.
 * Everything cryptographically sensitive arrives already encrypted from the browser.
 * The backend is a blind carrier — it stores and routes without reading.
 */
public record MessageRequest(
    String recipient,
    String threadId,            // null for new threads; client provides for replies
    String subject,             // Cleartext metadata — consciously accepted tradeoff
    String encryptedBody,       // AES-GCM(body), IV prepended, Base64
    String messageKey,          // AES key wrapped with recipient's X25519 public key (ECDH)
    String senderPublicKey,     // Ephemeral X25519 public key for ECDH unwrapping
    String senderBlindToken,    // HMAC-SHA256(senderEmail) — blind sender search index
    String encryptedSender,     // sender email encrypted to recipient's public key — for inbox display
    Set<String> searchTokens,   // HMAC-SHA256 keyword tokens for blind search (non-sealed only)
    boolean sealed             // If true: excluded from search, blind token index, and inbox list
) {}