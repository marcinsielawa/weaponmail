import { Component, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, RouterModule } from '@angular/router';
import { MessageService } from '../../services/message.service';
import { CryptoService } from '../../services/crypto.service';

@Component({
  selector: 'app-compose',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterModule],
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
    const target = this.recipient();
    const content = this.body();
    
    if (!target || !content) return;
    
    this.sending.set(true);
    try {
      // 1. Generate a one-time AES-GCM key for this message
      const aesKey = await this.crypto.generateMessageKey();
      
      // 2. Encrypt the body (WebCrypto API)
      // Note: CryptoService returns IV + Ciphertext as Base64
      const encryptedBody = await this.crypto.encryptBody(content, aesKey);
      
      // 3. Generate Blind Token for metadata privacy
      const senderToken = await this.crypto.generateBlindToken('marcin@weaponmail.io');

      // 4. Construct the Encrypted Envelope
      // NEXT STEP: We will implement ECDH to wrap the AES key properly!
      const payload = {
        recipient: target,
        subject: this.subject(),
        encryptedBody: encryptedBody,
        messageKey: 'PLACEHOLDER_WRAPPED_KEY', 
        senderPublicKey: 'PLACEHOLDER_EPHEMERAL_KEY',
        senderBlindToken: senderToken
      };

      this.messageService.sendMessage(payload).subscribe({
        next: () => {
          console.log('Message stored in vault.');
          this.router.navigate(['/inbox']);
        },
        error: (err) => {
          console.error('Vault rejection:', err);
          this.sending.set(false);
        }
      });

    } catch (e) {
      console.error('Encryption failed:', e);
      this.sending.set(false);
    }
  }
}