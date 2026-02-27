import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

/**
 * The Encrypted Envelope matching the backend's MessageRequest record.
 */
export interface MessageRequest {
  recipient: string;        // The recipient's vault address
  threadId?: string;       // Optional UUID for threading
  subject: string;         // Cleartext metadata (reference)
  
  // Security Payloads (Base64)
  encryptedBody: string;    // Body ciphertext (AES-GCM)
  messageKey: string;       // The AES body key, wrapped with ECDH shared secret
  senderPublicKey: string;  // Ephemeral X25519 public key used for ECDH
  
  // Zero-Knowledge Identity
  senderBlindToken: string; // HMAC-SHA256(sender) used for blind search
  encryptedSender: string;  // Sender's address encrypted for the recipient
  
  // Privacy Controls
  searchTokens: string[];   // HMAC tokens for keyword search
  sealed: boolean;         // If true, message is excluded from search/inbox indexes
  /** E2EE attachment blobs in the format "<filename>:<base64-ciphertext>". */
  attachments?: string[];
}

// The "Encrypted Envelope" interface (matches your Java Record)
export interface MessageSummary {
  id: string;
  threadId: string; // Required for partition key
  sender: string;
  subject: string;
  timestamp: number;
}

export interface MessageDetail {
  id: string;
  threadId: string;
  encryptedSender: string;
  subject: string;
  encryptedBody: string;
  messageKey: string;
  senderPublicKey: string;
  sealed: boolean;
  /** E2EE attachment blobs in the format "<filename>:<base64-ciphertext>". */
  attachments: string[];
}

@Injectable({ providedIn: 'root' })
export class MessageService {
  
  private apiUrl = '/api/messages';

  constructor(private http: HttpClient) { }

  /**
   * INBOX: Fetch all messages for a specific user
   */
  getInbox(recipient: string): Observable<MessageSummary[]> {
    return this.http.get<MessageSummary[]>(`${this.apiUrl}/${recipient}`);
  }

  getMessage(recipient: string, threadId: string, id: string): Observable<MessageDetail> {
    return this.http.get<MessageDetail>(`${this.apiUrl}/${recipient}/${threadId}/${id}`);
  }

  /**
   * SEND: Post a new encrypted envelope to the server
   */
  sendMessage(message: MessageRequest): Observable<void> {
    return this.http.post<void>(this.apiUrl, message);
  }

  /**
   * SEARCH: Find messages from a specific sender (Blind Token)
   */
  searchBySender(recipient: string, token: string): Observable<MessageSummary[]> {
    return this.http.get<MessageSummary[]>(`${this.apiUrl}/${recipient}/search/${token}`);
  }

  /**
   * SEARCH: Find messages by any blind token (sender, subject keyword, or body keyword).
   * Searches the searchTokens set stored on each message.
   */
  searchByToken(recipient: string, token: string): Observable<MessageSummary[]> {
    return this.http.get<MessageSummary[]>(`${this.apiUrl}/${recipient}/search/token/${token}`);
  }

  /**
   * THREAD: Get all messages in a conversation thread.
   */
  getThread(recipient: string, threadId: string): Observable<MessageSummary[]> {
    return this.http.get<MessageSummary[]>(`${this.apiUrl}/${recipient}/thread/${threadId}`);
  }
}