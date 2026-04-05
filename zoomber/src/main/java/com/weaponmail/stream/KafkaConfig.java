package com.weaponmail.stream;

import com.weaponmail.message.event.InboxEvent;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

/**
 * Kafka producer configuration.
 *
 * KafkaTemplate is thread-safe and its send() returns a CompletableFuture —
 * bridged to Mono in MessageService via Mono.fromFuture().
 * No reactor-kafka dependency needed on the producer side.
 */
@Configuration
public class KafkaConfig {
}