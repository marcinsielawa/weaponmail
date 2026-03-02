package com.weaponmail.stream;

import com.weaponmail.message.event.InboxEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Sinks;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Bridges Kafka → SSE using Spring's @KafkaListener.
 *
 * <p>Spring Boot 4 configures @KafkaListener containers to run on virtual threads by default
 * (via {@code spring.threads.virtual.enabled=true}). This means the blocking Kafka poll loop
 * inside the listener container is pinned to a cheap virtual thread — no event loop starvation,
 * no reactor-kafka complexity.
 *
 * <p>When an event arrives, it is emitted into the recipient's {@link Sinks.Many}. Any open
 * SSE connection ({@link InboxStreamController}) subscribed to that sink receives the event
 * immediately via the reactive Flux.
 */
@Service
public class InboxStreamService {

    private static final Logger log = LoggerFactory.getLogger(InboxStreamService.class);

    // One Sink per active recipient — lazily created on first SSE connect, cleaned up on disconnect.
    private final ConcurrentHashMap<String, Sinks.Many<InboxEvent>> sinks =
            new ConcurrentHashMap<>();

    /**
     * Kafka consumer — runs on a virtual thread (Spring Boot 4 default).
     * Blocking here is perfectly safe: the virtual thread is parked, not a platform thread.
     *
     * groupId matches application.yml spring.kafka.consumer.group-id
     */
    @KafkaListener(
        topics    = "${weaponmail.kafka.topics.inbox-events}",
        groupId   = "${spring.kafka.consumer.group-id}"
    )
    public void onInboxEvent(InboxEvent event) {
        Sinks.Many<InboxEvent> sink = sinks.get(event.recipient());
        if (sink == null) {
            // No browser currently connected for this recipient — event is intentionally dropped.
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
     * Called by {@link InboxStreamController} when a browser opens an SSE connection.
     * Creates (or reuses) a multicast Sink for this recipient and returns its Flux.
     */
    public Flux<InboxEvent> streamFor(String recipient) {
        Sinks.Many<InboxEvent> sink = sinks.computeIfAbsent(
                recipient,
                k -> Sinks.many().multicast().onBackpressureBuffer(128));

        return sink.asFlux()
                .doOnCancel(()    -> cleanup(recipient))
                .doOnTerminate(() -> cleanup(recipient));
    }

    private void cleanup(String recipient) {
        sinks.remove(recipient);
        log.debug("[SSE] Sink removed for {} (browser disconnected)", recipient);
    }
}