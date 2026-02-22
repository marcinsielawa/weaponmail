package com.weaponmail.message;

import java.util.UUID;

import org.springframework.data.cassandra.repository.ReactiveCassandraRepository;
import org.springframework.stereotype.Repository;

import reactor.core.publisher.Flux;

@Repository
public interface MessageRepository extends ReactiveCassandraRepository<MessageEntity, MessageKey> {

    // ScyllaDB will find these instantly because 'recipient' is the Partition Key
    Flux<MessageEntity> findAllByKeyRecipient(String recipient);

}
