import { ApplicationConfig, provideZonelessChangeDetection } from '@angular/core';
import { provideRouter } from '@angular/router';
import { provideHttpClient } from '@angular/common/http';
import { routes } from './app.routes';

import { Pbkdf2Strategy }       from './crypto/pbkdf2.strategy';
import { Argon2idStrategy }     from './crypto/argon2id.strategy';
import { KDF_STRATEGY, KDF_PARAMS, DEFAULT_KDF_PARAMS } from './crypto/kdf-strategy';

// ─── KDF SWITCH ─────────────────────────────────────────────────────────────
// Change this one line to swap the key derivation function across the whole app.
// 'pbkdf2'   → WebCrypto native, no WASM, works everywhere, weaker against GPUs
// 'argon2id' → Memory-hard, WASM (hash-wasm), strongly recommended for production
//const KDF: 'pbkdf2'; // 'pbkdf2' | 'argon2id' 
// ────────────────────────────────────────────────────────────────────────────

export const appConfig: ApplicationConfig = {
  providers: [
    provideZonelessChangeDetection(),
    provideRouter(routes),
    provideHttpClient(),

    // Register both strategies as injectables
    Pbkdf2Strategy,
    Argon2idStrategy,

    // Bind the active strategy to the token
    {
      provide:  KDF_STRATEGY,
     // useClass: KDF === 'argon2id' ? Argon2idStrategy : Pbkdf2Strategy,
      useClass: Argon2idStrategy
    },

    // Bind the parameters
    {
      provide:  KDF_PARAMS,
      useValue: DEFAULT_KDF_PARAMS,
    },
  ],
};