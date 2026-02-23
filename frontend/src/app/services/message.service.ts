import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

// The "Encrypted Envelope" interface (matches your Java Record)
export interface MessageRequest {
  recipient: string;
  threadId?: string;
  subject: string;
  encryptedBody: string;
  messageKey: string;
  senderPublicKey: string;
  senderBlindToken: string;
}

// The Summary interface (matches your Java MessageSummary)
export interface MessageSummary {
  id: string;
  sender: string;
  subject: string;
  timestamp: number;
}

@Injectable({
  providedIn: 'root'
})
export class MessageService {

  private apiUrl = '/api/messages';

  constructor(private http: HttpClient) { }

  /**
   * INBOX: Fetch all messages for a specific user
   */
  getInbox(recipient: string): Observable<MessageSummary[]> {
    return this.http.get<MessageSummary[]>(`${this.apiUrl}/${recipient}`);
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
}