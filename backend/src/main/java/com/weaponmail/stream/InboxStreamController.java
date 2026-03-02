package com.weaponmail.stream;

import com.weaponmail.message.event.InboxEvent;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;

@RestController
@RequestMapping("/api/stream")
public class InboxStreamController {

    private final InboxStreamService streamService;

    public InboxStreamController(InboxStreamService streamService) {
        this.streamService = streamService;
    }

    /**
     * GET /api/stream/{recipient}
     *
     * Returns a never-ending SSE stream. The browser's EventSource keeps
     * this connection alive. Each new message for this recipient triggers
     * an event that updates the Angular inbox signal in real time.
     *
     * Security note: In production, validate that the authenticated user
     * matches {recipient}. Add your authGuard / Spring Security here.
     */
    @GetMapping(value = "/{recipient}", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Flux<ServerSentEvent<InboxEvent>> streamInbox(@PathVariable String recipient) {
        return streamService.streamFor(recipient)
            .map(event -> ServerSentEvent.<InboxEvent>builder()
                .id(event.messageId())
                .event("new-message")
                .data(event)
                .build()
            );
    }
}