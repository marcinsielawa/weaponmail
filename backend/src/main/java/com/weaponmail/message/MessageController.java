package com.weaponmail.message;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/messages")
public class MessageController {
    
    private final MessageService messageService;
    
    public MessageController(MessageService messageService) {
        this.messageService = messageService;
    }
    
    @PostMapping
    public Mono<Void> sendMessage(@RequestBody MessageRequest request) {
        return messageService.sendMessage(request);
    }
    
    @GetMapping("/{recipient}")
    public Flux<MessageSummary> getInbox(@PathVariable String recipient) {
        return messageService.getMessages(recipient);
    }
    
    @GetMapping("/{recipient}/{threadId}/{id}")
    public Mono<MessageDetail> getMessage(
            @PathVariable String recipient,
            @PathVariable String threadId,
            @PathVariable String id) {
        return messageService.getMessageById(recipient, threadId, id);
    }

    /**
     * SEARCH: Find messages from a specific sender (using the blind token).
     */
    @GetMapping("/{recipient}/search/{token}")
    public Flux<MessageSummary> searchBySender(
            @PathVariable String recipient,
            @PathVariable String token) {
        return messageService.searchBySender(recipient, token);
    }

}
