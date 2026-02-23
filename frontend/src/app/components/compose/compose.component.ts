import { Component, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { MessageService } from '../../services/message.service';
import { CryptoService } from '../../services/crypto.service';

@Component({
  selector: 'app-compose',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './compose.component.html',
  styleUrl: './compose.component.scss'
})
export class ComposeComponent {
  
  recipient = signal('');
  subject = signal('');
  body = signal('');
  sending = signal(false);

  constructor(
    private messageService: MessageService,
    private crypto: CryptoService,
    private router: Router
  ) {}

  async send() {
    if (!this.recipient() || !this.body()) return;
    
    this.sending.set(true);
    try {
      // 1. Generate AES Key for this message
      const aesKey = await this.crypto.generateMessageKey();
      
      // 2. Encrypt the body
      const encryptedBody = await this.crypto.encryptBody(this.body(), aesKey);
      
      // 3. Generate Blind Token
      const senderToken = await this.crypto.generateBlindToken('marcin@weaponmail.io');

      // 4. Wrap Key (Simplified for now - we'll add ECDH wrapping next!)
      // For now, we'll send a placeholder for the wrapped key until we setup Recipient Public Keys
      const payload = {
        recipient: this.recipient(),
        subject: this.subject(),
        encryptedBody: encryptedBody,
        messageKey: 'PLACEHOLDER_WRAPPED_KEY', 
        senderPublicKey: 'PLACEHOLDER_PUB_KEY',
        senderBlindToken: senderToken
      };

      this.messageService.sendMessage(payload).subscribe({
        next: () => {
          this.router.navigate(['/inbox']);
        },
        error: (err) => {
          console.error('Failed to send encrypted envelope:', err);
          this.sending.set(false);
        }
      });

    } catch (e) {
      console.error('Encryption failed:', e);
      this.sending.set(false);
    }
  }
}