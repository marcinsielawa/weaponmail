import { inject } from '@angular/core';
import { Router, CanActivateFn } from '@angular/router';
import { AuthService } from '../services/auth.service';

/**
 * AuthGuard ensures that the user has a decrypted vault in memory.
 * If the page is refreshed, the private key is lost, and the user 
 * must log in again to re-derive the master key and decrypt the vault.
 */
export const authGuard: CanActivateFn = () => {
  const authService = inject(AuthService);
  const router = inject(Router);

  // Use the signal to check if the private key exists in memory
  if (authService.privateKeyBytes()) {
    return true;
  }

  // No key material? Redirect to login to unlock the vault again.
  return router.parseUrl('/login');
};