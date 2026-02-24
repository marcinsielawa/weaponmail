import { Component, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, RouterModule } from '@angular/router';
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterModule],
  templateUrl: './login.component.html',
  styleUrl: './login.component.scss'
})
export class LoginComponent {
  username = signal('');
  password = signal('');
  loading = signal(false);
  error = signal<string | null>(null);
  step = signal<'form' | 'decrypting' | 'done'>('form');

  constructor(private auth: AuthService, private router: Router) {}

  async submit() {
    this.error.set(null);
    this.loading.set(true);
    this.step.set('decrypting');

    try {
      await this.auth.login(this.username(), this.password());
      this.step.set('done');
      
      // Navigate to inbox after a short delay to show success state
      setTimeout(() => this.router.navigate(['/inbox']), 800);
    } catch (e: any) {
      this.error.set(e?.error?.message ?? 'Invalid username or password.');
      this.step.set('form');
    } finally {
      this.loading.set(false);
    }
  }
}