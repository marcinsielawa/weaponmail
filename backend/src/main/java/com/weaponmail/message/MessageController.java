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
    
    private MessageService service;

    public MessageController(MessageService service) {
        this.service = service;
    }

    @GetMapping("/{type}")
    public Flux<MessageSummary> getMessages(@PathVariable String type) {
        return service.getMessages(type);
    }

    @GetMapping("/view/{id}")
    public Mono<MessageDetail> getMessage(@PathVariable String id) {
        return service.getMessageById(id);
    }
    
    @PostMapping("/send")
    public Mono<MessageSummary> sendMessage(@RequestBody MessageRequest request) {
        return service.sendMessage(request);
    }

}
