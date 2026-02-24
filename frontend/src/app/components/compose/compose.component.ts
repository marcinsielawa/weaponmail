import { Component, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, RouterModule } from '@angular/router';
import { MessageService } from '../../services/message.service';
import { CryptoService } from '../../services/crypto.service';
import { AuthService } from '../../services/auth.service';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';

interface PublicKeyResponse {
  username: string;
  publicKey: string;
}

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
  sealed = signal(false); // Sealed message toggle

  constructor(
    private messageService: MessageService,
    private crypto: CryptoService,
    private auth: AuthService,
    private http: HttpClient,
    private router: Router
  ) {}

  async send() {
    const target = this.recipient();
    const content = this.body();
    const senderEmail = this.auth.currentUser();

    if (!target || !content || !senderEmail) return;

    const privateKeyBytes = this.auth.privateKeyBytes();
    if (!privateKeyBytes) {
      console.error('No private key in session — please log in again.');
      return;
    }

    this.sending.set(true);
    try {
      // 1. Fetch recipient's public key from server
      const pkResponse = await firstValueFrom(
        this.http.get<PublicKeyResponse>(`/api/account/${target}/public-key`)
      );
      const recipientPublicKeyBytes = this.crypto.fromBase64(pkResponse.publicKey);

      // 2. Full ECDH encryption: body + wrapped AES key + encrypted sender address
      const { encryptedBody, messageKey, ephemeralPublicKey, encryptedSender } =
        await this.crypto.encryptMessage(content, recipientPublicKeyBytes, senderEmail);

      // 3. Sender blind token (for search-by-sender)
      const senderBlindToken = await this.crypto.generateBlindToken(senderEmail);

      // 4. Blind keyword search tokens (omitted for sealed messages)
      let searchTokens: string[] = [];
      if (!this.sealed()) {
        // Derive search HMAC key — in a real flow this would be stored in AuthService
        // from login. For demo: re-derive from session (user must re-enter password — skip for demo)
        // Here we use a simplified approach: use the blind token key for keywords too
        const enc = new TextEncoder();
        const hmacKey = await window.crypto.subtle.importKey(
          'raw', enc.encode('weaponmail-search-key-demo'),
          { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
        );
        const keywords = this.crypto.extractKeywords(this.subject(), content);
        searchTokens = await this.crypto.generateSearchTokens(keywords, hmacKey);
      }

      // 5. Construct the Encrypted Envelope
      const payload = {
        recipient: target,
        subject: this.subject(),
        encryptedBody,
        messageKey,
        senderPublicKey: ephemeralPublicKey, // ephemeral key for ECDH
        senderBlindToken,
        encryptedSender,
        searchTokens,
        sealed: this.sealed()
      };

      this.messageService.sendMessage(payload as any).subscribe({
        next: () => {
          console.log('Message sealed and stored in vault.');
          this.router.navigate(['/inbox']);
        },
        error: (err) => {
          console.error('Vault rejection:', err);
          this.sending.set(false);
        }
      });

    } catch (e) {
      console.error('Encryption pipeline failed:', e);
      this.sending.set(false);
    }
  }
}