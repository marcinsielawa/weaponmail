package com.weaponmail.message;

import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import com.datastax.oss.driver.api.core.uuid.Uuids;
import com.weaponmail.message.event.InboxEvent;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Business logic for the WeaponMail message vault.
 *
 * <p><strong>Sealed message contract:</strong> Sealed messages are stored but excluded from all
 * listing, indexing, and search endpoints. The only way to access a sealed message is via direct
 * ID lookup ({@link #getMessageById}). The server enforces this invariant — the client cannot
 * bypass it by guessing a search token.
 *
 * <p><strong>Kafka integration:</strong> Uses {@link KafkaTemplate} whose {@code send()} returns
 * a {@link CompletableFuture}. Bridged to {@link Mono} via {@code Mono.fromFuture()} so the
 * WebFlux event loop is never blocked — the actual Kafka network I/O runs on Kafka's internal
 * sender thread. Virtual threads (Java 25 / Spring Boot 4 default) handle @KafkaListener on
 * the consumer side in {@link com.weaponmail.stream.InboxStreamService}.
 */
@Service
public class MessageService {

    private static final Logger log = LoggerFactory.getLogger(MessageService.class);

    private final MessageRepository repository;
    private final KafkaTemplate<String, InboxEvent> kafkaTemplate;

    @Value("${weaponmail.kafka.topics.inbox-events}")
    private String inboxEventsTopic;

    public MessageService(MessageRepository repository,
                          KafkaTemplate<String, InboxEvent> kafkaTemplate) {
        this.repository = repository;
        this.kafkaTemplate = kafkaTemplate;
    }

    // ── Read paths — unchanged, fully reactive ──────────────────────────────

    public Flux<MessageSummary> getMessages(String recipient) {
        return searchableMessages(recipient)
                .map(this::mapToSummary);
    }

    public Flux<MessageSummary> searchBySender(String recipient, String token) {
        return repository.findAllByKeyRecipientAndSenderBlindToken(recipient, token)
                .filter(entity -> !entity.isSealed())
                .map(this::mapToSummary);
    }

    public Flux<MessageSummary> searchByToken(String recipient, String token) {
        return searchableMessages(recipient)
                .filter(entity -> entity.getSearchTokens() != null
                        && entity.getSearchTokens().contains(token))
                .map(this::mapToSummary);
    }

    public Flux<MessageSummary> getThread(String recipient, String threadId) {
        return repository.findAllByKeyRecipientAndKeyThreadId(recipient, UUID.fromString(threadId))
                .filter(entity -> !entity.isSealed())
                .map(this::mapToSummary);
    }

    public Mono<MessageDetail> getMessageById(String recipient, String threadId, String id) {
        MessageKey key = new MessageKey(
                recipient,
                UUID.fromString(threadId),
                UUID.fromString(id));

        return repository.findById(key)
                .map(entity -> new MessageDetail(
                        entity.getKey().id().toString(),
                        entity.getKey().threadId().toString(),
                        entity.getEncryptedSender(),
                        entity.getSubject(),
                        entity.getEncryptedBody(),
                        entity.getMessageKey(),
                        entity.getSenderPublicKey(),
                        entity.isSealed()));
    }

    // ── Write path — reactive Scylla + non-blocking Kafka bridge ────────────

    /**
     * Persists the encrypted envelope to ScyllaDB, then publishes an {@link InboxEvent}
     * to Kafka — in that order, guaranteed by the reactive chain.
     *
     * <p>Flow:
     * <pre>
     *   repository.save()            — reactive, Cassandra driver I/O
     *     .flatMap(saved -> ...)
     *       Mono.fromFuture(          — bridges CompletableFuture → Mono
     *         kafkaTemplate.send()    — Kafka producer I/O on its internal sender thread
     *       )
     * </pre>
     *
     * <p>The WebFlux event loop thread is never parked/blocked at any point in this chain.
     * Kafka publishes only after ScyllaDB acknowledges — eliminating any read-before-write race
     * for the SSE consumer on the recipient's side.
     */
    public Mono<Void> sendMessage(MessageRequest request) {
        MessageEntity entity = buildEntity(request);

        return repository.save(entity)
                .flatMap(saved -> {
                    InboxEvent event = toEvent(saved);

                    // KafkaTemplate.send() → CompletableFuture<SendResult>
                    // Mono.fromFuture()    → subscribes the event loop without blocking it
                    // The Kafka producer's internal sender thread completes the future.
                    CompletableFuture<Void> sendFuture = kafkaTemplate
                            .send(inboxEventsTopic, event.recipient(), event)
                            .thenApply(_ -> null);  // SendResult → Void

                    return Mono.fromFuture(sendFuture)
                            .doOnSuccess(_ -> log.debug(
                                    "[Kafka] Published inbox event for {} | msg={}",
                                    event.recipient(), event.messageId()))
                            .doOnError(ex -> log.error(
                                    "[Kafka] Failed to publish event for {} | msg={} — {}",
                                    event.recipient(), event.messageId(), ex.getMessage()));
                });
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    private MessageEntity buildEntity(MessageRequest request) {
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

        return entity;
    }

    private InboxEvent toEvent(MessageEntity saved) {
        return new InboxEvent(
                saved.getKey().recipient(),
                saved.getKey().id().toString(),
                saved.getKey().threadId().toString(),
                saved.getSubject(),
                Uuids.unixTimestamp(saved.getKey().id()),
                saved.isSealed());
    }

    private MessageSummary mapToSummary(MessageEntity entity) {
        return new MessageSummary(
                entity.getKey().id().toString(),
                entity.getKey().threadId().toString(),
                entity.getEncryptedSender(),
                entity.getSubject(),
                Uuids.unixTimestamp(entity.getKey().id()),
                entity.isSealed(),
                entity.getSenderPublicKey());
    }

    private Flux<MessageEntity> searchableMessages(String recipient) {
        return repository.findAllByKeyRecipient(recipient)
                .filter(entity -> !entity.isSealed());
    }
}