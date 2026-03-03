# Weapon Mail

**A high-scale, zero-knowledge end-to-end encrypted messaging engine.**

Built with Spring Boot WebFlux, Apache Kafka, ScyllaDB, and Angular — engineered so the server is architecturally incapable of reading message contents.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                           Browser (Angular 21)                            │
│                                                                           │
│  ┌─────────────────────┐    ┌──────────────────────────────────────────┐  │
│  │    AuthService      │    │           CryptoService (WebCrypto)      │  │
│  │  signup · login     │    │  ECDH P-256 · AES-256-GCM · HMAC-SHA256 │  │
│  │  key pair bootstrap │    │  Argon2id KDF · blind search tokens      │  │
│  └──────────┬──────────┘    └───────────────────┬──────────────────────┘  │
│             │                                   │                         │
│  ┌──────────▼───────────────────────────────────▼──────────────────────┐  │
│  │                     InboxStreamService (SSE)                        │  │
│  │         EventSource → /api/stream/{recipient}                       │  │
│  │         Real-time push — no polling, auto-reconnect                 │  │
│  └──────────────────────────────┬───────────────────────────────────────┘  │
└─────────────────────────────────┼──────────────────────────────────────────┘
                                  │  HTTPS — only ciphertext crosses the wire
┌─────────────────────────────────▼──────────────────────────────────────────┐
│                  Spring Boot 4.x WebFlux Backend (Java 25)                  │
│                                                                             │
│  AccountController · MessageController · InboxStreamController              │
│  MessageService · InboxStreamService                                        │
│                                                                             │
│  Zero-knowledge guarantee: backend stores opaque ciphertext only.           │
│  It never holds a key capable of decrypting message bodies.                 │
│                                                                             │
│  Write path:  MessageService.sendMessage()                                  │
│    → ScyllaDB.save()          (reactive, Cassandra driver)                  │
│    → KafkaTemplate.send()     (bridges CompletableFuture → Mono,            │
│                                Kafka I/O on its own sender thread)          │
│                                                                             │
│  Read path:   MessageController                                             │
│    → ScyllaDB queries         (fully reactive Flux/Mono)                    │
│                                                                             │
│  SSE path:    InboxStreamController                                         │
│    → InboxStreamService.streamFor(recipient)   (Sinks.Many → Flux)          │
└──────────────┬──────────────────────────────────────────────────────────────┘
               │                                    │
               │  CQL (Cassandra driver)             │  Kafka protocol (KRaft)
               │                                    │
┌──────────────▼────────────────┐    ┌──────────────▼────────────────────────┐
│  ScyllaDB (Cassandra-compat.) │    │       Apache Kafka 3.9 (KRaft)        │
│                               │    │                                        │
│  accounts                     │    │  Topic: inbox-events                   │
│  messages                     │    │    key   = recipient (routing)         │
│  message_search_index         │    │    value = InboxEvent (JSON)           │
│                               │    │                                        │
│  Blind token secondary index  │    │  Producer: MessageService              │
│  HMAC search token lookup     │    │    acks=all · idempotent · retries=3   │
└───────────────────────────────┘    │  Consumer: InboxStreamService          │
                                     │    @KafkaListener on virtual thread    │
                                     │    → emits to recipient's SSE Sink     │
                                     └────────────────────────────────────────┘
``` 

### Message Flow: Send → Store → Stream

```
Browser (Sender)
  │  1. Generate ephemeral ECDH key pair
  │  2. Derive shared secret with recipient's public key
  │  3. Encrypt body with AES-256-GCM (random bodyKey)
  │  4. Wrap bodyKey with ECDH shared secret
  │  5. Compute HMAC blind tokens (sender identity + search keywords)
  │  6. POST /api/messages  — only ciphertext leaves the browser
  ▼
Spring Boot (MessageService)
  │  7. Persist encrypted envelope to ScyllaDB  (reactive save)
  │  8. Publish InboxEvent to Kafka topic inbox-events
  │     — contains only: recipient, messageId, threadId, subject, timestamp
  │     — encrypted body / messageKey / senderPublicKey NOT included
  ▼
Apache Kafka (topic: inbox-events)
  │  9. Routes event to InboxStreamService consumer (virtual thread)
  ▼
InboxStreamService
  │  10. Looks up recipient's Sinks.Many, emits InboxEvent
  ▼
Browser (Recipient — SSE / EventSource)
  │  11. Receives push notification, prepends to inbox
  │  12. On open: fetches full message detail via REST (decrypts client-side)
```

---

## Zero-Knowledge Properties

| Property | Mechanism |
|---|---|
| **Body confidentiality** | AES-256-GCM encrypted client-side before transmission. Server stores opaque ciphertext. |
| **Sender anonymity** | Sender identity encrypted to recipient's public key. Server holds only an HMAC blind token. |
| **Keyword search privacy** | Search tokens are HMAC-SHA256 digests derived from the user's master key. Server matches tokens without knowing keywords. |
| **Key confidentiality** | Private keys are wrapped with an Argon2id-derived master key — the master key never leaves the browser. |
| **Forward secrecy** | Each message uses a fresh ephemeral ECDH key pair, discarded after send. Compromising the long-term private key does not expose past message bodies. |
| **Kafka event safety** | InboxEvent published to Kafka contains zero cryptographic material — only routing metadata the server already holds. |

---

## Technology Stack

| Layer | Technology | Role |
|---|---|---|
| Frontend | Angular 21 (zoneless) | SPA — all cryptographic operations run exclusively in the browser |
| Crypto (frontend) | WebCrypto API — P-256 / AES-256-GCM | Native ECDH key agreement and symmetric authenticated encryption |
| KDF | Argon2id (hash-wasm) · PBKDF2-SHA256 fallback | Password-based master key derivation; strategy pattern allows DI swap |
| Real-time | Server-Sent Events (EventSource) | Push inbox notifications from backend to browser |
| Backend | Spring Boot 4.x WebFlux (Java 25) | Non-blocking reactive REST API; all DB calls return `Mono` / `Flux` |
| Message broker | Apache Kafka 3.9 (KRaft — no ZooKeeper) | Decouples message persistence from real-time SSE fan-out |
| Database | ScyllaDB (Cassandra-compatible) | High-throughput distributed storage; blind token secondary indexes |
| Crypto (backend) | BouncyCastle `bcprov-jdk18on` | X25519 key pair generation in test utilities |
| Transport | TLS | All traffic encrypted in transit; only ciphertext payloads reach the server |

---

## Security & Cryptography Documentation

Full threat model, key derivation scheme, message encryption flow, blind search design, and known tradeoffs:

→ [`SECURITY.md`](./SECURITY.md)