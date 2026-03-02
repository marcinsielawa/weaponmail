import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, Router, RouterModule } from '@angular/router';
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
  message       = signal<MessageDetail | null>(null);
  decryptedBody = signal<string>('');
  decryptedSender = signal<string>('');
  loading       = signal(true);
  error         = signal<string | null>(null);  // NY: synlig felstatus i template

  constructor(
    private route:          ActivatedRoute,
    private messageService: MessageService,
    private crypto:         CryptoService,
    private auth:           AuthService,
    private router:         Router
  ) {}

  ngOnInit(): void {
    const params    = this.route.snapshot.params;
    const recipient = params['recipient'];
    const threadId  = params['threadId'];
    const id        = params['id'];

    // Guard: om privKey saknas (session gick ut) — skicka till login
    if (!this.auth.privateKeyBytes()) {
      console.warn('[MessageDetail] No private key in session — redirecting to login');
      this.router.navigate(['/login']);
      return;
    }

    this.messageService.getMessage(recipient, threadId, id).subscribe({
      // BUG FIX: next är INTE async — vi kedjar promises korrekt istället
      // Tidigare: async next() kastade undantag som subscribe() inte fångade
      next: (msg) => {
        this.message.set(msg);
        // Kör dekryptering som ett separat promise-chain utanför subscribe
        this.decrypt(msg).catch(e => {
          console.error('[MessageDetail] Unexpected decrypt error:', e);
          this.decryptedBody.set('[Error: Decryption pipeline failed]');
          this.loading.set(false);
        });
      },
      // BUG FIX: error-handler saknades helt — loading hängde för evigt
      error: (err) => {
        console.error('[MessageDetail] Failed to fetch message from vault:', err);
        this.error.set(
          err.status === 404
            ? 'Message not found in vault.'
            : `Vault error (${err.status ?? 'network'}): could not load message.`
        );
        this.loading.set(false);
      }
    });
  }

  private async decrypt(msg: MessageDetail): Promise<void> {
    const privKey = this.auth.privateKeyBytes();

    // Defensivt: kontrollera igen (användaren kan ha förlorat sessionen)
    if (!privKey) {
      this.error.set('Session expired — private key no longer in memory. Please log in again.');
      this.loading.set(false);
      return;
    }

    // Meddelanden som kom via SSE-event saknar encryptedSender/senderPublicKey
    // — de hämtas alltid kompletta via REST här, så detta ska alltid vara ok
    if (!msg.encryptedBody || !msg.messageKey || !msg.senderPublicKey) {
      this.error.set('Incomplete message data received from vault.');
      this.loading.set(false);
      return;
    }

    try {
      const [body, sender] = await Promise.all([
        this.crypto.decryptMessage(
          msg.encryptedBody,
          msg.messageKey,
          msg.senderPublicKey,
          privKey
        ),
        this.crypto.decryptSender(
          msg.encryptedSender,
          msg.senderPublicKey,
          privKey
        )
      ]);

      this.decryptedBody.set(body);
      this.decryptedSender.set(sender);
    } catch (e) {
      console.error('[MessageDetail] Decryption failed:', e);
      this.decryptedBody.set('[Error: Could not decrypt — wrong key or corrupted data]');
      this.decryptedSender.set('[Unknown]');
      // Visa ändå meddelandet (med feltext) — don't hide the whole view
    } finally {
      // ALLTID sätt loading = false, oavsett om decrypt lyckades eller inte
      this.loading.set(false);
    }
  }

  reply(): void {
    const msg    = this.message();
    const params = this.route.snapshot.params;
    if (!msg) return;
    this.router.navigate(['/compose/reply', params['recipient'], msg.threadId, msg.id]);
  }

  forward(): void {
    const msg    = this.message();
    const params = this.route.snapshot.params;
    if (!msg) return;
    this.router.navigate(['/compose/forward', params['recipient'], msg.threadId, msg.id]);
  }
}