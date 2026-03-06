package com.weaponmail.stream;

import com.weaponmail.message.event.InboxEvent;

import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.annotation.EnableKafka;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.core.ConsumerFactory;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;
import org.springframework.kafka.support.serializer.JsonDeserializer;
import org.springframework.kafka.support.serializer.JsonSerializer;

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

    @Value("${spring.kafka.bootstrap-servers}")
    private String bootstrapServers;

    @Bean
    ProducerFactory<String, InboxEvent> inboxEventProducerFactory() {
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
    KafkaTemplate<String, InboxEvent> kafkaTemplate(
            ProducerFactory<String, InboxEvent> factory) {
        return new KafkaTemplate<>(factory);
    }
    
    @Bean
    ConcurrentKafkaListenerContainerFactory<String, InboxEvent> kafkaListenerContainerFactory(
            ConsumerFactory<String, InboxEvent> consumerFactory) {
        ConcurrentKafkaListenerContainerFactory<String, InboxEvent> factory = 
            new ConcurrentKafkaListenerContainerFactory<>();
        factory.setConsumerFactory(consumerFactory);
        return factory;
    }

    @Bean
    ConsumerFactory<String, InboxEvent> consumerFactory() {
        Map<String, Object> props = new HashMap<>();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, "localhost:9092");
        props.put(ConsumerConfig.GROUP_ID_CONFIG, "weaponmail-v1");
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, JsonDeserializer.class);
        
        // Viktigt: Tala om för JsonDeserializer vilken klass den ska skapa
        props.put(JsonDeserializer.TRUSTED_PACKAGES, "com.weaponmail.message.event");
        props.put(JsonDeserializer.VALUE_DEFAULT_TYPE, "com.weaponmail.message.event.InboxEvent");
        
        return new DefaultKafkaConsumerFactory<>(props, new StringDeserializer(), 
            new JsonDeserializer<>(InboxEvent.class, false));
    }
}