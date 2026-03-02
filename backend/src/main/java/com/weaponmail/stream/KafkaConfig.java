package com.weaponmail.stream;

import com.weaponmail.message.event.InboxEvent;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;
import org.springframework.kafka.support.serializer.JsonSerializer;

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

    @Value("${spring.kafka.bootstrap-servers}")
    private String bootstrapServers;

    @Bean
    public ProducerFactory<String, InboxEvent> inboxEventProducerFactory() {
        return new DefaultKafkaProducerFactory<>(Map.of(
            ProducerConfig.BOOTSTRAP_SERVERS_CONFIG,       bootstrapServers,
            ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG,    StringSerializer.class,
            ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG,  JsonSerializer.class,
            ProducerConfig.ACKS_CONFIG,                    "all",
            ProducerConfig.RETRIES_CONFIG,                 3,
            ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG,      true   // exactly-once producer
        ));
    }

    @Bean
    public KafkaTemplate<String, InboxEvent> kafkaTemplate(
            ProducerFactory<String, InboxEvent> factory) {
        return new KafkaTemplate<>(factory);
    }
}