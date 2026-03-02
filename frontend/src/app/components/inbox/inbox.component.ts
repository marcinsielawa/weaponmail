import { Component, OnDestroy, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router, RouterModule } from '@angular/router';
import { Subscription } from 'rxjs';

import { AuthService } from '../../services/auth.service';
import { CryptoService } from '../../services/crypto.service';
import { MessageService, MessageSummary } from '../../services/message.service';
import { InboxStreamService, InboxEvent } from '../../services/inbox-stream.service';

@Component({
  selector: 'app-inbox',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './inbox.component.html',
  styleUrl: './inbox.component.scss'
})
export class InboxComponent implements OnInit, OnDestroy {
  private auth          = inject(AuthService);
  private messageService = inject(MessageService);
  private router         = inject(Router);
  private crypto         = inject(CryptoService);
  private stream         = inject(InboxStreamService);

  messages  = signal<MessageSummary[]>([]);
  loading   = signal<boolean>(false);
  recipient = this.auth.currentUser;

  private streamSub?: Subscription;

  ngOnInit(): void {
    const user = this.recipient();
    if (!user) {
      this.router.navigate(['/login']);
      return;
    }

    // 1. Ladda befintliga meddelanden från ScyllaDB
    this.refreshInbox();

    // 2. Öppna SSE-koppling — nya meddelanden dyker upp direkt
    this.stream.connect(user);
    this.streamSub = this.stream.inboxEvent$.subscribe(event => {
      this.onNewMessageEvent(event);
    });
  }

  ngOnDestroy(): void {
    // Stäng SSE när komponenten förstörs (navigerar bort från inbox)
    this.stream.disconnect();
    this.streamSub?.unsubscribe();
  }

  refreshInbox(): void {
    const user = this.recipient();
    if (!user) return;

    this.loading.set(true);
    this.messageService.getInbox(user).subscribe({
      next: async (data) => {
        this.messages.set(data);
        this.loading.set(false);
        await this.decryptSenders(data);
      },
      error: (err) => {
        console.error('Vault access failed:', err);
        this.loading.set(false);
      }
    });
  }

  /**
   * Anropas av SSE-streamen när ett nytt meddelande anländer.
   * Prepend:ar en ny MessageSummary-rad direkt i signalen —
   * ingen page reload, noll latens.
   *
   * Obs: encryptedSender och senderPublicKey är INTE i Kafka-eventen
   * (zero-knowledge design). Vi sätter placeholders — de fylls i
   * när användaren faktiskt öppnar meddelandet (MessageDetailComponent
   * fetchar hela detaljen via REST ändå).
   */
  private onNewMessageEvent(event: InboxEvent): void {
    const newSummary: MessageSummary = {
      id:              event.messageId,
      threadId:        event.threadId,
      subject:         event.subject,
      timestamp:       event.timestamp,
      sealed:          event.sealed,
      encryptedSender: '',    // Saknas i Kafka-event av säkerhetsskäl — se JSDoc
      senderPublicKey: '',    // Saknas i Kafka-event av säkerhetsskäl
      decryptedSender: event.sealed ? undefined : '🔔 New Message',
    };

    // Prepend — nyaste meddelandet hamnar överst
    this.messages.update(prev => [newSummary, ...prev]);
  }

  /**
   * BUG FIX: Navigera med recipient från auth-tjänsten, INTE från meddelandet.
   * Tidigare: this.recipient() kunde vara null om signalen inte var satt.
   * Nu: vi loggar och navigerar bara om recipient finns.
   */
  openMessage(msg: MessageSummary): void {
    const user = this.recipient();
    if (!user) {
      // Ska inte hända — authGuard skyddar den här routen
      console.error('[Inbox] openMessage called but no authenticated user in session');
      this.router.navigate(['/login']);
      return;
    }
    // Route: /message/:recipient/:threadId/:id
    this.router.navigate(['/message', user, msg.threadId, msg.id]);
  }

  private async decryptSenders(summaries: MessageSummary[]): Promise<void> {
    const privKey = this.auth.privateKeyBytes();
    if (!privKey) return;

    for (const msg of summaries) {
      if (msg.sealed || !msg.encryptedSender || !msg.senderPublicKey) continue;

      try {
        msg.decryptedSender = await this.crypto.decryptSender(
          msg.encryptedSender,
          msg.senderPublicKey,
          privKey
        );
      } catch {
        msg.decryptedSender = '[Unknown Sender]';
      }
    }
    // Trigga signal-uppdatering
    this.messages.set([...summaries]);
  }
}