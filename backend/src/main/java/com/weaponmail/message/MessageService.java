package com.weaponmail.message;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.springframework.stereotype.Service;

import com.datastax.oss.driver.api.core.uuid.Uuids;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Business logic for the WeaponMail message vault.
 *
 * <p><strong>Sealed message contract:</strong> Sealed messages are stored but excluded from all
 * listing, indexing, and search endpoints. The only way to access a sealed message is via direct
 * ID lookup ({@link #getMessageById}). The server enforces this invariant — the client cannot
 * bypass it by guessing a search token.
 */
@Service
public class MessageService {

    private final MessageRepository repository;

    public MessageService(MessageRepository repository) {
        this.repository = repository;
    }

    public Flux<MessageSummary> getMessages(String recipient) {
        return searchableMessages(recipient)
                .map(this::mapToSummary);
    }

    public Mono<Void> sendMessage(MessageRequest request) {
        MessageEntity entity = new MessageEntity();

        UUID threadId = (request.threadId() != null)
                ? UUID.fromString(request.threadId())
                : UUID.randomUUID();

        entity.setKey(new MessageKey(request.recipient(), threadId, Uuids.timeBased()));
        entity.setSubject(request.subject());
        entity.setEncryptedBody(request.encryptedBody());
        entity.setMessageKey(request.messageKey());
        entity.setSenderPublicKey(request.senderPublicKey());
        entity.setSenderBlindToken(request.senderBlindToken());
        entity.setEncryptedSender(request.encryptedSender());
        entity.setSearchTokens(request.searchTokens() != null ? request.searchTokens() : Set.of());
        entity.setSealed(request.sealed());
//        entity.setAttachments(request.attachments() != null ? request.attachments() : List.of());

        return repository.save(entity).then();
    }

    /**
     * Blind sender search — excluded for sealed messages.
     * The token is HMAC-SHA256(senderEmail) so the server matches
     * it without knowing the sender's identity.
     */
    public Flux<MessageSummary> searchBySender(String recipient, String token) {
        return repository.findAllByKeyRecipientAndSenderBlindToken(recipient, token)
                .filter(entity -> !entity.isSealed())
                .map(this::mapToSummary);
    }

    /**
     * Blind search by any search token (sender, subject keyword, or body keyword).
     * Searches the {@code searchTokens} set stored on each message, which contains
     * HMAC tokens for subject words and body keywords in addition to the sender token.
     * Sealed messages are excluded.
     */
    public Flux<MessageSummary> searchByToken(String recipient, String token) {
        return searchableMessages(recipient)
                .filter(entity -> entity.getSearchTokens() != null
                        && entity.getSearchTokens().contains(token))
                .map(this::mapToSummary);
    }

    /**
     * Returns all messages in a thread for a recipient, excluding sealed messages.
     */
    public Flux<MessageSummary> getThread(String recipient, String threadId) {
        return repository.findAllByKeyRecipientAndKeyThreadId(recipient, UUID.fromString(threadId))
                .filter(entity -> !entity.isSealed())
                .map(this::mapToSummary);
    }

    /**
     * Maps a MessageEntity to an inbox summary.
     *
     * encryptedSender replaces the old hardcoded "ANONYMOUS" string.
     * The client receives the opaque ciphertext and decrypts it locally
     * using ECDH(recipient.priv, senderPublicKey) to display the sender name —
     * exactly as Proton Mail does, without the server ever seeing the sender.
     */
    private MessageSummary mapToSummary(MessageEntity entity) {
        return new MessageSummary(
                entity.getKey().id().toString(),
                entity.getKey().threadId().toString(),
                entity.getEncryptedSender(),   // was "ANONYMOUS" — client decrypts this
                entity.getSubject(),
                Uuids.unixTimestamp(entity.getKey().id()),
                entity.isSealed(),
                entity.getSenderPublicKey()
        );
    }

    /**
     * Direct message lookup by composite key (recipient + threadId + id).
     * This is the only path that can return sealed messages — the client
     * must already know the exact message ID to access it.
     */
    public Mono<MessageDetail> getMessageById(String recipient, String threadId, String id) {
        MessageKey key = new MessageKey(
                recipient,
                UUID.fromString(threadId),
                UUID.fromString(id)
        );

        return repository.findById(key)
                .map(entity -> new MessageDetail(
                        entity.getKey().id().toString(),
                        entity.getKey().threadId().toString(),
                        entity.getEncryptedSender(),   // was "ANONYMOUS"
                        entity.getSubject(),
                        entity.getEncryptedBody(),
                        entity.getMessageKey(),
                        entity.getSenderPublicKey(),
                        entity.isSealed()
                       // entity.getAttachments() != null ? entity.getAttachments() : List.of()
                ));
    }

    /**
     * Returns all non-sealed messages for a recipient.
     * Central helper enforcing the sealed-message exclusion invariant for all
     * listing and search paths. Only {@link #getMessageById} bypasses this filter.
     */
    private Flux<MessageEntity> searchableMessages(String recipient) {
        return repository.findAllByKeyRecipient(recipient)
                .filter(entity -> !entity.isSealed());
    }
}