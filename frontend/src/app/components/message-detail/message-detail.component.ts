import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, RouterModule } from '@angular/router';
import { MessageService, MessageDetail } from '../../services/message.service';
import { CryptoService } from '../../services/crypto.service';
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-message-detail',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './message-detail.component.html',
  styleUrl: './message-detail.component.scss'
})
export class MessageDetailComponent implements OnInit {
  message = signal<MessageDetail | null>(null);
  decryptedBody = signal<string>('');
  decryptedSender = signal<string>('');
  loading = signal(true);

  constructor(
    private route: ActivatedRoute,
    private messageService: MessageService,
    private crypto: CryptoService,
    private auth: AuthService
  ) {}

  async ngOnInit() {
    const params = this.route.snapshot.params;
    const recipient = params['recipient'];
    const threadId = params['threadId'];
    const id = params['id'];

    this.messageService.getMessage(recipient, threadId, id).subscribe({
      next: async (msg) => {
        this.message.set(msg);
        await this.decrypt(msg);
        this.loading.set(false);
      }
    });
  }

  private async decrypt(msg: MessageDetail) {
    const privKey = this.auth.privateKeyBytes();
    if (!privKey) return;

    try {
      // 1. Decrypt the Body
      const body = await this.crypto.decryptMessage(
        msg.encryptedBody,
        msg.messageKey,
        msg.senderPublicKey,
        privKey
      );
      this.decryptedBody.set(body);

      // 2. Decrypt the Sender's actual identity
      const sender = await this.crypto.decryptSender(
        msg.encryptedSender,
        msg.senderPublicKey,
        privKey
      );
      this.decryptedSender.set(sender);
    } catch (e) {
      console.error('Decryption failed. Vault key may be incorrect.', e);
      this.decryptedBody.set('[Error: Could not decrypt message contents]');
    }
  }
}