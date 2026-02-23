import { Routes } from '@angular/router';
import { InboxComponent } from './components/inbox/inbox.component';
import { ComposeComponent } from './components/compose/compose.component';

export const routes: Routes = [
  { path: '', redirectTo: 'inbox', pathMatch: 'full' },
  { path: 'inbox', component: InboxComponent },
  { path: 'compose', component: ComposeComponent }
];