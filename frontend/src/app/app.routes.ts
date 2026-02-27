import { Routes } from '@angular/router';
import { InboxComponent } from './components/inbox/inbox.component';
import { ComposeComponent } from './components/compose/compose.component';
import { SignupComponent } from './components/signup/signup.component';
import { LoginComponent } from './components/login/login.component';
import { MessageDetailComponent } from './components/message-detail/message-detail.component';
import { authGuard } from './guards/auth.guard';

export const routes: Routes = [
  // Public Routes
  { path: '', redirectTo: 'login', pathMatch: 'full' },
  { path: 'login', component: LoginComponent },
  { path: 'signup', component: SignupComponent },

  // Protected Vault Routes
  { 
    path: 'inbox', 
    component: InboxComponent, 
    canActivate: [authGuard] 
  },
  { 
    path: 'compose', 
    component: ComposeComponent, 
    canActivate: [authGuard] 
  },
  { 
    path: 'compose/reply/:recipient/:threadId/:originalId', 
    component: ComposeComponent, 
    canActivate: [authGuard] 
  },
  { 
    path: 'compose/forward/:recipient/:threadId/:originalId', 
    component: ComposeComponent, 
    canActivate: [authGuard] 
  },
  { 
    path: 'message/:recipient/:threadId/:id', 
    component: MessageDetailComponent,
    canActivate: [authGuard] 
  },

  // Fallback
  { path: '**', redirectTo: 'login' }
];