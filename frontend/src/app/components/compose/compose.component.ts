import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterModule } from '@angular/router';
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
export class ComposeComponent implements OnInit {
  recipient = signal('');
  subject = signal('');
  body = signal('');
  sending = signal(false);
  sealed = signal(false); // Sealed message toggle

  /** threadId pre-populated in reply/forward mode */
  threadId = signal<string | null>(null);
  /** 'reply' | 'forward' | null */
  mode = signal<'reply' | 'forward' | null>(null);

  constructor(
    private messageService: MessageService,
    private crypto: CryptoService,
    private auth: AuthService,
    private http: HttpClient,
    private router: Router,
    private route: ActivatedRoute
  ) {}

  async ngOnInit() {
    const params = this.route.snapshot.params;
    const originalId = params['originalId'];
    const threadId = params['threadId'];
    const recipientParam = params['recipient'];

    // Detect compose mode from route URL (first path segment is 'reply' or 'forward')
    const firstSegment = this.route.snapshot.url[0]?.path;
    if (firstSegment === 'reply') {
      this.mode.set('reply');
    } else if (firstSegment === 'forward') {
      this.mode.set('forward');
    }

    if (this.mode() && originalId && threadId && recipientParam) {
      this.threadId.set(threadId);
      // Load original message for context
      try {
        const msg = await firstValueFrom(
          this.messageService.getMessage(recipientParam, threadId, originalId)
        );
        if (this.mode() === 'reply') {
          this.recipient.set(recipientParam);
          this.subject.set(`Re: ${msg.subject}`);
        } else if (this.mode() === 'forward') {
          this.subject.set(`Fwd: ${msg.subject}`);
          // Decrypt body for forward context
          const privKey = this.auth.privateKeyBytes();
          if (privKey) {
            try {
              const decrypted = await this.crypto.decryptMessage(
                msg.encryptedBody, msg.messageKey, msg.senderPublicKey, privKey
              );
              this.body.set(`\n\n--- Forwarded Message ---\n${decrypted}`);
            } catch {
              this.body.set('\n\n--- Forwarded Message ---\n[Could not decrypt original]');
            }
          }
        }
      } catch {
        // ignore if original message not found
      }
    }
  }

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

      // 2. Full X25519 ECDH encryption: body + wrapped AES key + encrypted sender address
      const { encryptedBody, messageKey, ephemeralPublicKey, encryptedSender } =
        await this.crypto.encryptMessage(content, recipientPublicKeyBytes, senderEmail);

      // 3. Sender blind token (for search-by-sender)
      const senderBlindToken = await this.crypto.generateBlindToken(senderEmail);

      // 4. Blind keyword search tokens — subject + body (omitted for sealed messages)
      let searchTokens: string[] = [];
      if (!this.sealed()) {
        const enc = new TextEncoder();
        const hmacKey = await window.crypto.subtle.importKey(
          'raw', enc.encode('weaponmail-search-key-demo'),
          { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
        );
        // Merge subject tokens and body tokens for comprehensive blind search
        const subjectTokens = await this.crypto.generateSubjectTokens(this.subject(), hmacKey);
        const keywords = this.crypto.extractKeywords(this.subject(), content);
        const bodyTokens = await this.crypto.generateSearchTokens(keywords, hmacKey);
        searchTokens = [...new Set([...subjectTokens, ...bodyTokens])];
      }

      // 5. Construct the Encrypted Envelope
      const payload = {
        recipient: target,
        threadId: this.threadId() ?? undefined,
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