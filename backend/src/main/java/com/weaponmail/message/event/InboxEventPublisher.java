package com.weaponmail.message.event;

import reactor.core.publisher.Mono;

public interface InboxEventPublisher {
    Mono<Void> publish(InboxEvent event);
}