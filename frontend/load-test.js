import http from 'k6/http';
import { check, sleep } from 'k6';
import { uuidv4 } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';

export const options = {
  stages: [
    { duration: '1m', target: 50 }, 
    { duration: '2m', target: 150 },
    { duration: '1m', target: 0 },
  ],
};

export default function () {
  const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
  const aliceId = uuidv4();
  const bobId = uuidv4();
  const testSubject = `Subject ${aliceId}`;

  const headers = { 'Content-Type': 'application/json' };

  // 1. Alice & Bob Signup (Corrected field names)
  http.post(`${BASE_URL}/api/account/signup`, JSON.stringify({
    username: `alice_${aliceId}`,
    publicKey: `alice_pk_${aliceId}`
  }), { headers });

  http.post(`${BASE_URL}/api/account/signup`, JSON.stringify({
    username: `bob_${bobId}`,
    publicKey: `bob_pk_${bobId}`
  }), { headers });

  // 2. Alice sends to Bob (Using properties from MessageRequest.java)
  const sendMessage = http.post(`${BASE_URL}/api/messages`, JSON.stringify({
    recipient: `bob_${bobId}`,
    subject: testSubject,
    encryptedBody: `body_${aliceId}`,
    messageKey: `key_${aliceId}`,
    senderPublicKey: `alice_pk_${aliceId}`,
    encryptedSender: `enc_sender_alice_${aliceId}`,
    sealed: false
  }), { headers });

  check(sendMessage, { 'Message sent': (r) => r.status === 200 });

  // 3. Bob retrieves inbox (Using properties from MessageSummary.java)
  let messageFound = false;
  let retries = 5;

  while (retries > 0 && !messageFound) {
    const bobInbox = http.get(`${BASE_URL}/api/messages/bob_${bobId}`, { headers });
    const messages = bobInbox.json();

    if (Array.isArray(messages) && messages.length > 0) {
      messageFound = true;
      check(bobInbox, {
        'Bob sees Alice pk': (r) => r.json()[0].senderPublicKey === `alice_pk_${aliceId}`,
        'Bob sees correct subject': (r) => r.json()[0].subject === testSubject
      });
    } else {
      retries--;
      sleep(0.5);
    }
  }

  check(messageFound, { 'Message arrived in ScyllaDB': (v) => v === true });
}