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
            .map(entity -> new MessageSummary(
                entity.getKey().id().toString(),
                "ANONYMOUS",
                entity.getSubject(),
                Uuids.unixTimestamp(entity.getKey().id()) // Extract the time from the ID!
            ));
    }
    public Mono<Void> sendMessage(MessageRequest request) {
        MessageEntity entity = new MessageEntity();
        entity.setKey(new MessageKey(request.recipient(), Uuids.timeBased()));
        entity.setSubject(request.subject());          // Record access!
        entity.setEncryptedBody(request.encryptedBody());
        entity.setMessageKey(request.messageKey());
        entity.setSenderPublicKey(request.senderPublicKey());

        return repository.save(entity).then();
    }

    
    public Mono<MessageDetail> getMessageById(String recipient, String id) {
        
        MessageKey key = new MessageKey(recipient, UUID.fromString(id));
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
