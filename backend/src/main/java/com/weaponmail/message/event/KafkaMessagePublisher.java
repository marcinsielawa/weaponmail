package com.weaponmail.message.event;

import java.util.concurrent.CompletableFuture;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

import reactor.core.publisher.Mono;

@Component
public class KafkaMessagePublisher implements InboxEventPublisher {
    
    private final KafkaTemplate<String, InboxEvent> kafkaTemplate;

    private String inboxEventsTopic;

    public KafkaMessagePublisher(KafkaTemplate<String, InboxEvent> kafkaTemplate, 
                                 @Value("${weaponmail.kafka.topics.inbox-events}") String topic) {
        this.kafkaTemplate = kafkaTemplate;
        this.inboxEventsTopic = topic;
    }

    @Override
    public Mono<Void> publish(InboxEvent event) {
        
       System.out.println("KuKafka - - - InboxEvent event " + inboxEventsTopic + " " + event);
        
     // KafkaTemplate.send() → CompletableFuture<SendResult>
        // Mono.fromFuture()    → subscribes the event loop without blocking it
        // The Kafka producer's internal sender thread completes the future.

        CompletableFuture<Void> sendFuture = kafkaTemplate
             .send(inboxEventsTopic, event.recipient(), event)
             .thenApply(_ -> null);  // SendResult → Void

        return Mono.fromFuture(sendFuture);
    }
}