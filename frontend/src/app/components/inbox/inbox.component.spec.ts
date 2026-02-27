import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { of } from 'rxjs';
import { InboxComponent } from './inbox.component';
import { MessageService } from '../../services/message.service';
import { AuthService } from '../../services/auth.service';

describe('InboxComponent', () => {
  let mockMessageService: Partial<MessageService>;
  let mockAuthService: Partial<AuthService>;

  beforeEach(async () => {
    mockMessageService = {
      getInbox: () =>
        of([
          {
            id: 'msg-1',
            threadId: 'thread-1',
            sender: 'enc-sender-blob',
            subject: 'Hello',
            timestamp: 1700000000000,
          },
        ]),
    };

    mockAuthService = {
      currentUser: (() => 'alice@weaponmail.io') as any,
      isLoggedIn: () => true,
    };

    await TestBed.configureTestingModule({
      imports: [InboxComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: MessageService, useValue: mockMessageService },
        { provide: AuthService, useValue: mockAuthService },
      ],
    }).compileComponents();
  });

  it('should create the component', () => {
    const fixture = TestBed.createComponent(InboxComponent);
    expect(fixture.componentInstance).toBeTruthy();
  });

  it('should load messages from the inbox on init', async () => {
    const fixture = TestBed.createComponent(InboxComponent);
    fixture.detectChanges();
    await fixture.whenStable();

    const component = fixture.componentInstance;
    expect(component.messages().length).toBe(1);
    expect(component.messages()[0].subject).toBe('Hello');
  });

  it('should render inbox messages in the template', async () => {
    const fixture = TestBed.createComponent(InboxComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('Hello');
  });
});
