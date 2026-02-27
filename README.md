# Weapon Mail

Weapon Mail is a high-scale, zero-knowledge E2EE messaging engine built with Spring Boot WebFlux, ScyllaDB, and Curve25519.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        Browser (Angular)                     │
│  ┌────────────────┐   ┌──────────────────────────────────┐  │
│  │  Auth Service  │   │       CryptoService (WebCrypto)  │  │
│  │  (signup/login)│   │  ECDH P-256 · AES-GCM · HMAC    │  │
│  └───────┬────────┘   └────────────────┬─────────────────┘  │
│          │  TLS (encrypted payloads only)                    │
└──────────┼──────────────────────────────────────────────────┘
           │
┌──────────▼──────────────────────────────────────────────────┐
│             Spring Boot WebFlux Backend (Java 25)            │
│   AccountController · MessageController · MessageService     │
│   Zero-knowledge: stores only ciphertext, never reads body   │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                   ScyllaDB (Cassandra-compatible)            │
│   accounts · messages · message_search_index tables          │
└─────────────────────────────────────────────────────────────┘
```

### Zero-Knowledge Properties
- Message bodies are **AES-GCM encrypted client-side** before leaving the browser
- The server stores an opaque `encryptedBody` blob — it cannot read the content
- Sender identity is hidden: only an HMAC blind token and an encrypted blob are stored
- Keyword search uses HMAC tokens — the server matches without knowing the keywords
- Private keys are wrapped with an Argon2id-derived master key and stored encrypted

---

## Technology Stack

| Layer | Technology | Purpose |
|---|---|---|
| Frontend | Angular 21 | SPA — all crypto runs in the browser |
| Crypto (frontend) | WebCrypto API (P-256 / AES-GCM) | Native ECDH key agreement + symmetric encryption |
| KDF | Argon2id (hash-wasm) / PBKDF2-SHA256 | Password-based master key derivation |
| Backend | Spring Boot 4.x WebFlux (Java 25) | Non-blocking reactive REST API |
| Crypto (backend tests) | BouncyCastle (`bcprov-jdk18on`) | X25519 key pairs in test utilities |
| Database | ScyllaDB (Cassandra-compatible) | High-throughput distributed message storage |
| Transport | TLS | Protects metadata in transit |

---

## Local Development Setup

### Prerequisites
- Java 25+ (for backend)
- Node.js 22+ and npm 11+ (for frontend)
- Docker and Docker Compose (for ScyllaDB)

### 1. Start ScyllaDB

```bash
docker-compose up -d scylladb
```

Wait ~30 seconds for ScyllaDB to start, then apply the schema:

```bash
docker exec -i weaponmail-db cqlsh < backend/src/main/resources/schema.cql
```

### 2. Start the backend

```bash
cd backend
./mvnw spring-boot:run
```

The API will be available at `http://localhost:8080`.

### 3. Start the frontend

```bash
cd frontend
npm install
npm start
```

The Angular dev server will be available at `http://localhost:4200` and will proxy API calls to the backend.

### 4. Run backend tests (no database required)

```bash
cd backend
./mvnw test
```

All tests mock the Cassandra repositories so they run without a live ScyllaDB.

### 5. Run frontend tests

```bash
cd frontend
npm test
```

---

## Security & Cryptography Documentation

- [`SECURITY.md`](./SECURITY.md) — Full threat model, crypto design, and known tradeoffs

