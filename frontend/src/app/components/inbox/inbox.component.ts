import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MessageService, MessageSummary } from '../../services/message.service';

@Component({
  selector: 'app-inbox',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './inbox.component.html',
  styleUrl: './inbox.component.scss'
})
export class InboxComponent implements OnInit {

  // SIGNALS: The source of truth
  messages = signal<MessageSummary[]>([]);
  loading = signal<boolean>(false);
  recipient = signal<string>('marcin@weaponmail.io');

  constructor(private messageService: MessageService) { }

  ngOnInit(): void {
    this.refreshInbox();
  }

  refreshInbox(): void {
    this.loading.set(true);
    this.messageService.getInbox(this.recipient()).subscribe({
      next: (data) => {
        this.messages.set(data);
        this.loading.set(false);
      },
      error: (err) => {
        console.error('Vault access failed:', err);
        this.loading.set(false);
      }
    });
  }
}