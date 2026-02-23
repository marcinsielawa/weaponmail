package com.weaponmail.message;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Service;

import com.datastax.oss.driver.api.core.uuid.Uuids;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Service
public class MessageService {

    private final MessageRepository repository;

    public MessageService(MessageRepository repository) {
        this.repository = repository;
    }

    public Flux<MessageSummary> getMessages(String recipient) {
        return repository.findAllByKeyRecipient(recipient)
            .map(this::mapToSummary);
    }

    public Mono<Void> sendMessage(MessageRequest request) {
        MessageEntity entity = new MessageEntity();
        
        // Handle Threading: Use existing threadId or generate a fresh one
        UUID threadId = (request.threadId() != null) 
            ? UUID.fromString(request.threadId()) 
            : UUID.randomUUID();

        entity.setKey(new MessageKey(request.recipient(), threadId, Uuids.timeBased()));
        entity.setSubject(request.subject());
        entity.setEncryptedBody(request.encryptedBody());
        entity.setMessageKey(request.messageKey());
        entity.setSenderPublicKey(request.senderPublicKey());
        entity.setSenderBlindToken(request.senderBlindToken());

        return repository.save(entity).then();
    }

    public Flux<MessageSummary> searchBySender(String recipient, String token) {
        return repository.findAllByKeyRecipientAndSenderBlindToken(recipient, token)
            .map(this::mapToSummary);
    }

    private MessageSummary mapToSummary(MessageEntity entity) {
        return new MessageSummary(
            entity.getKey().id().toString(),
            entity.getKey().threadId().toString(), // Map the thread ID
            "ANONYMOUS",
            entity.getSubject(),
            Uuids.unixTimestamp(entity.getKey().id())
        );
    }
    
    // The "Weaponized" 3-param lookup
    public Mono<MessageDetail> getMessageById(String recipient, String threadId, String id) {
        MessageKey key = new MessageKey(
            recipient, 
            UUID.fromString(threadId), 
            UUID.fromString(id)
        );
        
        return repository.findById(key) 
                .map(entity -> new MessageDetail(
                    entity.getKey().id().toString(),
                    "ANONYMOUS",
                    entity.getSubject(),
                    entity.getEncryptedBody(),
                    entity.getMessageKey(),
                    entity.getSenderPublicKey()
                ));
    }

}
