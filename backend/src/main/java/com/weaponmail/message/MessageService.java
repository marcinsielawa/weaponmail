package com.weaponmail.message;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Service;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Service
public class MessageService {

    private final ConcurrentHashMap<String, List<MessageSummary>> database = new ConcurrentHashMap<>();

    private final ConcurrentHashMap<String, MessageDetail> messageStore = new ConcurrentHashMap<>();

    public MessageService() {
        database.put("INBOX", new ArrayList<>());
        database.put("SENT", new ArrayList<>());
    }

    public Flux<MessageSummary> getMessages(String type) {
        return Flux.fromIterable(database.getOrDefault(type.toUpperCase(), Collections.emptyList()));
    }

    public Mono<MessageSummary> sendMessage(MessageRequest request) {
        return Mono.fromRunnable(() -> {
            MessageSummary summary = new MessageSummary();

            summary.id = UUID.randomUUID().toString();
            summary.sender = "me@weaponmail.io";
            summary.subject = request.subject;
            summary.timestamp = System.currentTimeMillis();
            
            MessageDetail detail = new MessageDetail();
            detail.id = summary.id;
            detail.sender = summary.sender;
            detail.subject = summary.subject;
            detail.encryptedBody = request.encryptedBody;
            detail.messageKey = request.messageKey;
            detail.senderPublicKey = request.senderPublicKey;
            
            messageStore.put(summary.id, detail);

            database.get("INBOX").add(summary);
            database.get("SENT").add(summary);

        });
    }

    public Mono<MessageDetail> getMessageById(String id) {
        return Mono.justOrEmpty(messageStore.get(id));
    }

}
