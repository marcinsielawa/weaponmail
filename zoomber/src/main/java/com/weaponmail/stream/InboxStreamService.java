package com.weaponmail.stream;

import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.weaponmail.message.event.InboxEvent;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Sinks;

/**
 * Bridges Kafka → SSE using Spring's @KafkaListener.
 *
 * <p>
 * Spring Boot 4 configures @KafkaListener containers to run on virtual threads
 * by default (via {@code spring.threads.virtual.enabled=true}). This means the
 * blocking Kafka poll loop inside the listener container is pinned to a cheap
 * virtual thread — no event loop starvation, no reactor-kafka complexity.
 *
 * <p>
 * When an event arrives, it is emitted into the recipient's {@link Sinks.Many}.
 * Any open SSE connection ({@link InboxStreamController}) subscribed to that
 * sink receives the event immediately via the reactive Flux.
 */
@Service
public class InboxStreamService {

    private static final Logger log = LoggerFactory.getLogger(InboxStreamService.class);

    // One Sink per active recipient — lazily created on first SSE connect, cleaned
    // up on disconnect.
    private final ConcurrentHashMap<String, Sinks.Many<InboxEvent>> sinks = new ConcurrentHashMap<>();

    /**
     * Kafka consumer — runs on a virtual thread (Spring Boot 4 default). Blocking
     * here is perfectly safe: the virtual thread is parked, not a platform thread.
     *
     * groupId matches application.yml spring.kafka.consumer.group-id
     */
    public void onInboxEvent(InboxEvent event) {
        log.debug("[SSE] Received event from Kafka for recipient: '{}'", event.recipient()); 
        Sinks.Many<InboxEvent> sink = sinks.get(event.recipient());
        if (sink == null) {
            // No browser currently connected for this recipient — event is intentionally
            // dropped.
            // The browser will do a full REST fetch of the inbox on next login/reconnect.
            log.debug("[SSE] No active sink for {} — event dropped (recipient offline)", event.recipient());
            return;
        }

        Sinks.EmitResult result = sink.tryEmitNext(event);
        if (result.isFailure()) {
            log.warn("[SSE] Failed to emit to sink for {}: {}", event.recipient(), result);
        } else {
            log.debug("[SSE] Emitted inbox event to {} | msg={}", event.recipient(), event.messageId());
        }
    }

    /**
     * Called by {@link InboxStreamController} when a browser opens an SSE
     * connection. Creates (or reuses) a multicast Sink for this recipient and
     * returns its Flux.
     */
    public Flux<InboxEvent> streamFor(String recipient) {
        log.debug("[SSE] New subscription request for {}", recipient);

        Sinks.Many<InboxEvent> sink = sinks.computeIfAbsent(
                recipient,
                _ -> Sinks.many().multicast().onBackpressureBuffer(256, false));

        return sink.asFlux()
                .doOnSubscribe(sub -> log.debug("[SSE] Client subscribed to flux for {}", recipient))
                .doFinally(signal -> {
                    log.debug("[SSE] Flux terminated for {} — signal: {}", recipient, signal);
                    cleanup(recipient);
                });
    }

    private void cleanup(String recipient) {
        sinks.computeIfPresent(recipient, (key, sink) -> {
            if (sink.currentSubscriberCount() == 0) {
                log.debug("[SSE] Sink removed for {} (no more subscribers)", recipient);
                return null;
            } else {
                log.debug("[SSE] Client disconnected for {}, keeping sink active (subscribers: {})",
                        recipient, sink.currentSubscriberCount());
                return sink;
            }
        });
    }
}