package com.weaponmail.message;

import org.springframework.data.cassandra.core.mapping.Column;
import org.springframework.data.cassandra.core.mapping.PrimaryKey;
import org.springframework.data.cassandra.core.mapping.Table;
import java.util.Set;

@Table("messages")
public class MessageEntity {

    @PrimaryKey
    private MessageKey key;

    @Column("subject")
    private String subject;

    @Column("encrypted_body")
    private String encryptedBody;

    @Column("message_key")
    private String messageKey;

    @Column("sender_public_key")
    private String senderPublicKey;

    @Column("sender_blind_token")
    private String senderBlindToken;

    /**
     * The sender's email address encrypted to the recipient's public key (X25519 + AES-GCM).
     * The server stores this as an opaque blob — only the recipient can decrypt it.
     * This allows Proton Mail-style sender display in the inbox without leaking sender identity.
     */
    @Column("encrypted_sender")
    private String encryptedSender;

    /**
     * HMAC-SHA256 keyword tokens for blind encrypted search.
     * Computed client-side using a search key derived from the user's master key.
     * The server stores and matches these without knowing what keywords they represent.
     */
    @Column("search_tokens")
    private Set<String> searchTokens;

    /**
     * Sealed messages are excluded from search, blind-token lookups,
     * and the general inbox listing. Only accessible by direct ID lookup.
     * The sender can toggle this per-message in the compose UI.
     */
    @Column("sealed")
    private boolean sealed;

    public MessageEntity() {}

    // Getters & Setters
    public MessageKey getKey() { return key; }
    public void setKey(MessageKey key) { this.key = key; }
    public String getSubject() { return subject; }
    public void setSubject(String subject) { this.subject = subject; }
    public String getEncryptedBody() { return encryptedBody; }
    public void setEncryptedBody(String encryptedBody) { this.encryptedBody = encryptedBody; }
    public String getMessageKey() { return messageKey; }
    public void setMessageKey(String messageKey) { this.messageKey = messageKey; }
    public String getSenderPublicKey() { return senderPublicKey; }
    public void setSenderPublicKey(String senderPublicKey) { this.senderPublicKey = senderPublicKey; }
    public String getSenderBlindToken() { return senderBlindToken; }
    public void setSenderBlindToken(String senderBlindToken) { this.senderBlindToken = senderBlindToken; }
    public String getEncryptedSender() { return encryptedSender; }
    public void setEncryptedSender(String encryptedSender) { this.encryptedSender = encryptedSender; }
    public Set<String> getSearchTokens() { return searchTokens; }
    public void setSearchTokens(Set<String> searchTokens) { this.searchTokens = searchTokens; }
    public boolean isSealed() { return sealed; }
    public void setSealed(boolean sealed) { this.sealed = sealed; }
}