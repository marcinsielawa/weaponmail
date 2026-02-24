import { Component, OnInit, signal, inject } from '@angular/core'; // Added inject
import { CommonModule } from '@angular/common';
import { Router, RouterModule } from '@angular/router';
import { MessageService, MessageSummary } from '../../services/message.service';
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-inbox',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './inbox.component.html',
  styleUrl: './inbox.component.scss'
})
export class InboxComponent implements OnInit {
  // Use inject() to allow field initialization
  private auth = inject(AuthService);
  private messageService = inject(MessageService);
  private router = inject(Router);

  messages = signal<MessageSummary[]>([]);
  loading = signal<boolean>(false);
  
  // Now this works because 'auth' is initialized immediately
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
}