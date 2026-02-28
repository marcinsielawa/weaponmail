import { Component, OnInit, signal, inject } from '@angular/core'; // Added inject
import { CommonModule } from '@angular/common';
import { Router, RouterModule } from '@angular/router';
import { MessageService, MessageSummary } from '../../services/message.service';
import { AuthService } from '../../services/auth.service';
import { CryptoService } from '../../services/crypto.service';

@Component({
  selector: 'app-inbox',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './inbox.component.html',
  styleUrl: './inbox.component.scss'
})
export class InboxComponent implements OnInit {
  private auth = inject(AuthService);
  private messageService = inject(MessageService);
  private router = inject(Router);
  private crypto = inject(CryptoService);

  messages = signal<MessageSummary[]>([]);
  loading = signal<boolean>(false);
  
  recipient = this.auth.currentUser;

  ngOnInit(): void {
    const user = this.recipient();
    if (!user) {
      this.router.navigate(['/login']);
      return;
    }
    this.refreshInbox();
  }

  refreshInbox(): void {
    const user = this.recipient();
    if (!user) return;

    this.loading.set(true);
    this.messageService.getInbox(user).subscribe({
      next: (data) => {
        this.messages.set(data);
        this.loading.set(false);
        this.decryptSenders(data);
      },
      error: (err) => {
        console.error('Vault access failed:', err);
        this.loading.set(false);
      }
    });
  }

  openMessage(msg: MessageSummary) {
    this.router.navigate(['/message', this.recipient(), msg.threadId, msg.id]);
  }

  /**
   * Decrypts senders asynchronously. 
   * For "gazillions" of messages, this won't block the UI because 
   * each decryption is an awaited microtask.
   */
  private async decryptSenders(summaries: MessageSummary[]) {
    const privKey = this.auth.privateKeyBytes();
    if (!privKey) return;

    // Process in parallel. browser's WebCrypto handles the threading.
    for (const msg of summaries) {
      if (msg.sealed) continue; // Sealed messages are skipped or handled differently

      try {
        const decrypted = await this.crypto.decryptSender(
          msg.encryptedSender,
          msg.senderPublicKey,
          privKey
        );
        msg.decryptedSender = decrypted;
      } catch (e) {
        msg.decryptedSender = '[Unknown Sender]';
      }
    }
    // Trigger signal update if needed (since we modified objects inside the array)
    this.messages.set([...summaries]);
  }  
}