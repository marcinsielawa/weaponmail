import { Component, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, RouterModule } from '@angular/router';
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-signup',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterModule],
  templateUrl: './signup.component.html',
  styleUrl: './signup.component.scss'
})
export class SignupComponent {
  username = signal('');
  password = signal('');
  confirmPassword = signal('');
  loading = signal(false);
  error = signal<string | null>(null);
  step = signal<'form' | 'generating' | 'done'>('form');

  constructor(private auth: AuthService, private router: Router) {}

  async submit() {
    this.error.set(null);
    if (this.password() !== this.confirmPassword()) {
      this.error.set('Passwords do not match.');
      return;
    }
    if (this.password().length < 12) {
      this.error.set('Password must be at least 12 characters for secure key derivation.');
      return;
    }

    this.step.set('generating');
    this.loading.set(true);

    try {
      await this.auth.signUp(this.username(), this.password());
      this.step.set('done');
      setTimeout(() => this.router.navigate(['/inbox']), 1500);
    } catch (e: any) {
      this.error.set(e?.error?.message ?? 'Signup failed. Username may already be taken.');
      this.step.set('form');
    } finally {
      this.loading.set(false);
    }
  }
}