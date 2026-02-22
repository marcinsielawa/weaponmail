package com.weaponmail.message;

import org.springframework.data.cassandra.core.mapping.Column;
import org.springframework.data.cassandra.core.mapping.PrimaryKey;
import org.springframework.data.cassandra.core.mapping.Table;

@Table("messages")
public class MessageEntity {

    @PrimaryKey
    private MessageKey key; // This now holds both recipient and id

    @Column("subject")
    private String subject;

    @Column("encrypted_body")
    private String encryptedBody;

    @Column("message_key")
    private String messageKey;

    @Column("sender_public_key")
    private String senderPublicKey;

    public MessageEntity() {}

    // --- Getters & Setters ---
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
}