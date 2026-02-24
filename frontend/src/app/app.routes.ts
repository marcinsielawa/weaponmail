import { Routes } from '@angular/router';
import { InboxComponent } from './components/inbox/inbox.component';
import { ComposeComponent } from './components/compose/compose.component';
import { SignupComponent } from './components/signup/signup.component';

export const routes: Routes = [
  { path: '', redirectTo: 'signup', pathMatch: 'full' },
  { path: 'signup', component: SignupComponent },
  { path: 'inbox', component: InboxComponent },
  { path: 'compose', component: ComposeComponent }
];