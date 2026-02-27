import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { MessageService, MessageRequest, MessageSummary, MessageDetail } from './message.service';

describe('MessageService', () => {
  let service: MessageService;
  let httpTesting: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        MessageService,
        provideHttpClient(),
        provideHttpClientTesting(),
      ],
    });
    service = TestBed.inject(MessageService);
    httpTesting = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpTesting.verify();
  });

  // ── sendMessage ────────────────────────────────────────────────────────────

  it('should POST to /api/messages when sendMessage is called', () => {
    const request: MessageRequest = {
      recipient: 'alice@weaponmail.io',
      subject: 'Secret',
      encryptedBody: 'enc-body',
      messageKey: 'wrapped-key',
      senderPublicKey: 'eph-pub',
      senderBlindToken: 'blind-token',
      encryptedSender: 'enc-sender',
      searchTokens: ['tok1'],
      sealed: false,
    };

    service.sendMessage(request).subscribe();

    const req = httpTesting.expectOne('/api/messages');
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual(request);
    req.flush(null);
  });

  // ── getInbox ───────────────────────────────────────────────────────────────

  it('should GET /api/messages/{recipient} when getInbox is called', () => {
    const mockSummaries: MessageSummary[] = [
      {
        id: 'msg-id-1',
        threadId: 'thread-id-1',
        sender: 'enc-sender-blob',
        subject: 'Test Subject',
        timestamp: 1700000000000,
      },
    ];

    service.getInbox('alice@weaponmail.io').subscribe((summaries) => {
      expect(summaries).toEqual(mockSummaries);
    });

    const req = httpTesting.expectOne('/api/messages/alice@weaponmail.io');
    expect(req.request.method).toBe('GET');
    req.flush(mockSummaries);
  });

  // ── getMessage ─────────────────────────────────────────────────────────────

  it('should GET /api/messages/{recipient}/{threadId}/{id} when getMessage is called', () => {
    const mockDetail: MessageDetail = {
      id: 'msg-id-1',
      threadId: 'thread-id-1',
      encryptedSender: 'enc-sender-blob',
      subject: 'Test Subject',
      encryptedBody: 'enc-body',
      messageKey: 'wrapped-key',
      senderPublicKey: 'eph-pub',
    };

    service.getMessage('alice@weaponmail.io', 'thread-id-1', 'msg-id-1').subscribe((detail) => {
      expect(detail).toEqual(mockDetail);
    });

    const req = httpTesting.expectOne(
      '/api/messages/alice@weaponmail.io/thread-id-1/msg-id-1'
    );
    expect(req.request.method).toBe('GET');
    req.flush(mockDetail);
  });

  // ── searchBySender ─────────────────────────────────────────────────────────

  it('should GET /api/messages/{recipient}/search/{token} when searchBySender is called', () => {
    const mockSummaries: MessageSummary[] = [
      {
        id: 'msg-id-2',
        threadId: 'thread-id-2',
        sender: 'enc-sender-blob',
        subject: 'From Sender',
        timestamp: 1700000001000,
      },
    ];

    service.searchBySender('alice@weaponmail.io', 'blind-token-abc').subscribe((summaries) => {
      expect(summaries).toEqual(mockSummaries);
    });

    const req = httpTesting.expectOne(
      '/api/messages/alice@weaponmail.io/search/blind-token-abc'
    );
    expect(req.request.method).toBe('GET');
    req.flush(mockSummaries);
  });
});
