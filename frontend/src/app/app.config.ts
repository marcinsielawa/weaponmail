import { ApplicationConfig, provideZonelessChangeDetection } from '@angular/core';
import { provideRouter } from '@angular/router';
import { provideHttpClient } from '@angular/common/http';
import { routes } from './app.routes';

import { Pbkdf2Strategy }       from './crypto/pbkdf2.strategy';
import { Argon2idStrategy }     from './crypto/argon2id.strategy';
import { KDF_STRATEGY, KDF_PARAMS, DEFAULT_KDF_PARAMS } from './crypto/kdf-strategy';

export const appConfig: ApplicationConfig = {
  providers: [
    provideZonelessChangeDetection(),
    provideRouter(routes),
    provideHttpClient(),

    // Register both strategies as injectables.
    // Pbkdf2Strategy is available as a DI override for unit tests only — never use it in production.
    Pbkdf2Strategy,
    Argon2idStrategy,

    /**
     * Argon2id is the only production KDF.
     * PBKDF2 strategy is available as a DI override for unit tests only — never use it in production.
     */
    {
      provide:  KDF_STRATEGY,
      useClass: Argon2idStrategy,
    },

    // Bind the parameters
    {
      provide:  KDF_PARAMS,
      useValue: DEFAULT_KDF_PARAMS,
    },
  ],
};