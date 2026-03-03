import { Injectable, OnDestroy } from '@angular/core';
import { Subject } from 'rxjs';

export interface InboxEvent {
  recipient: string;
  messageId: string;
  threadId: string;
  subject: string;
  timestamp: number;
  sealed: boolean;
}

/**
 * Öppnar en native EventSource (SSE) mot /api/stream/{recipient}.
 * Kafka-events från backend emitteras direkt hit → inbox uppdateras
 * utan polling eller page refresh.
 *
 * EventSource återansluter automatiskt vid nätverksfel — ingen
 * manuell retry-logik behövs.
 */
@Injectable({ providedIn: 'root' })
export class InboxStreamService implements OnDestroy {

  private eventSource: EventSource | null = null;
  private eventSubject = new Subject<InboxEvent>();

  /** Subscribe på detta för att ta emot live inbox-events */
  readonly inboxEvent$ = this.eventSubject.asObservable();

  connect(recipient: string): void {
    // Stäng eventuell tidigare koppling innan vi öppnar en ny
    this.disconnect();

    if (this.eventSubject.closed) {
        this.eventSubject = new Subject<InboxEvent>();
    }

    const url = `/api/stream/${encodeURIComponent(recipient)}`;
    this.eventSource = new EventSource(url);

    this.eventSource.addEventListener('new-message', (e: MessageEvent) => {
      try {
        const event: InboxEvent = JSON.parse(e.data);
        this.eventSubject.next(event);
      } catch {
        console.error('[SSE] Failed to parse event:', e.data);
      }
    });

    this.eventSource.onerror = () => {
      // Logga men gör inget — EventSource hanterar reconnect automatiskt
      console.warn('[SSE] Connection error — browser will reconnect automatically');
    };

    console.debug('[SSE] Connected to', url);
  }

  disconnect(): void {
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
      console.debug('[SSE] Disconnected');
    }
  }

  ngOnDestroy(): void {
    this.disconnect();
    this.eventSubject.complete();
  }
}