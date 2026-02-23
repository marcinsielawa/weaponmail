package com.weaponmail.message;

import org.springframework.data.cassandra.repository.ReactiveCassandraRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import java.util.UUID;

@Repository
public interface MessageRepository extends ReactiveCassandraRepository<MessageEntity, MessageKey> {

    Flux<MessageEntity> findAllByKeyRecipient(String recipient);

    // ZERO-KNOWLEDGE SEARCH: Find specific sender token within recipient's inbox
    Flux<MessageEntity> findAllByKeyRecipientAndSenderBlindToken(String recipient, String token);
    
    // THREADING: Find all messages in a specific conversation
    Flux<MessageEntity> findAllByKeyRecipientAndKeyThreadId(String recipient, UUID threadId);
}