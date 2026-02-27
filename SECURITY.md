# Security & Cryptography Design

This document describes the zero-knowledge end-to-end encryption (E2EE) design of Weapon Mail, its threat model, key derivation scheme, and known tradeoffs.

---

## Threat Model

### What the server sees
| Field | Value at rest | Notes |
|---|---|---|
| `recipient` | Plaintext email address | Needed for routing |
| `subject` | Plaintext | Consciously accepted tradeoff — see Known Tradeoffs |
| `encryptedBody` | AES-GCM ciphertext | Server cannot read body |
| `messageKey` | AES key wrapped with recipient public key | Server cannot unwrap |
| `senderPublicKey` | Ephemeral P-256 public key (65 bytes, raw) | No identity by itself |
| `senderBlindToken` | HMAC-SHA256(senderEmail, fixed salt) | Server sees the hash, not the email |
| `encryptedSender` | Sender email encrypted to recipient's public key | Server cannot read sender identity |
| `searchTokens` | Set of HMAC-SHA256 keyword hashes | Server matches tokens blindly |
| `sealed` | Boolean | When true: excluded from search and inbox listing |

### What the server does NOT see
- The plaintext message body
- The sender's email address (only an HMAC and an encrypted blob)
- The content of search keywords (only derived HMAC tokens)
- The user's master password (only a SHA-256 hash is transmitted for login)
- The user's raw private key (only the AES-GCM-encrypted form is stored)

### Attacker model
- **Honest-but-curious server**: The server correctly executes the protocol but may log everything it receives. The E2EE design ensures the server learns nothing about message contents.
- **Network attacker**: All communications are over TLS. The server only receives already-encrypted payloads.
- **Compromised server database**: An attacker who exfiltrates the database gains ciphertext only — no private keys and no plaintext bodies.

---

## Key Derivation Scheme

### Master Key (login)

```
password ──► Argon2id(t=1, m=64MiB, p=4, len=32) ──► masterKey (AES-256)
                  │
             passwordSalt (random 32 bytes, stored server-side)
```

- **Algorithm**: Argon2id (RFC 9106), memory-hard — resistant to GPU/ASIC brute-force
- **Fallback**: PBKDF2-SHA256 with 600 000 iterations (OWASP 2023) for environments where WASM is restricted
- **KDF strategy pattern**: `KdfStrategy` interface allows swapping between Argon2id and PBKDF2 without changing callers
- The derived `masterKey` **never leaves the browser** — only the AES-GCM-encrypted private key is stored server-side

### Search HMAC Key

```
password + salt + "-search" ──► PBKDF2-SHA256(100 000 iters) ──► searchHmacKey (HMAC-SHA256)
```

- Derived separately from the master key so keyword search capability can be revoked independently
- PBKDF2 (not Argon2id) because search tokens don't protect private key material; memory-hardness is unnecessary here

### Login Hash

```
password ──► SHA-256 ──► loginHash (sent to server for authentication)
```

- The server verifies `loginHash` — it never receives the raw password
- Note: SHA-256 is not memory-hard; this is acceptable because the server-side verification only prevents replay attacks. The actual key derivation (Argon2id) happens client-side.

---

## Message Encryption Flow (ECDH + AES-GCM)

```
Sender:
  1. Generate ephemeral P-256 key pair (ephPub, ephPriv)
  2. Generate random 256-bit AES body key (bodyKey)
  3. encryptedBody = AES-GCM(bodyKey, plainBody)          // random IV prepended
  4. sharedSecret = ECDH(ephPriv, recipientPub)
  5. messageKey = AES-GCM(sharedSecret, bodyKey)           // wraps the body key
  6. encryptedSender = AES-GCM(sharedSecret, senderEmail)  // hides sender identity

Recipient:
  1. sharedSecret = ECDH(recipientPriv, ephPub)            // same secret via commutativity
  2. bodyKey = AES-GCM⁻¹(sharedSecret, messageKey)
  3. plainBody = AES-GCM⁻¹(bodyKey, encryptedBody)
  4. senderEmail = AES-GCM⁻¹(sharedSecret, encryptedSender)
```

### Properties
- **Perfect forward secrecy**: Each message uses a fresh ephemeral key pair. Compromising the recipient's long-term private key does not expose past messages (since the ephemeral key is discarded after sending).
- **Authenticated encryption**: AES-GCM includes a 128-bit authentication tag. Any tampering with the ciphertext causes decryption to fail with an exception.
- **Double-key envelope**: The body is encrypted with a random `bodyKey`, and `bodyKey` is encrypted with the ECDH shared secret. This matches the signal/PGP envelope pattern.

---

## Blind Token / Zero-Knowledge Search Design

### Sender Blind Token

```
senderBlindToken = HMAC-SHA256(key="weaponmail-blind-token-salt-v1", data=senderEmail.toLowerCase())
```

- The server stores and indexes `senderBlindToken`
- To find all messages from Alice, the client computes her token and queries the server
- The server matches on the token without ever knowing Alice's email address
- **Known limitation**: The salt is a fixed, publicly known constant (not a per-user secret). An attacker who knows a candidate email can precompute its token offline and probe the index. Protection against enumeration relies on rate-limiting and authenticated endpoints, not secrecy of the salt.

### Search Token (keyword search)

```
searchToken[keyword] = HMAC-SHA256(searchHmacKey, keyword.toLowerCase().trim())
```

- `searchHmacKey` is derived from the user's master key (PBKDF2, scoped with `-search` suffix)
- Tokens are computed client-side and stored server-side as opaque blobs
- The server matches keyword queries without knowing what the keywords are
- If a user revokes their `searchHmacKey`, previously stored search tokens become unmatchable

---

## Known Tradeoffs

| Tradeoff | Description |
|---|---|
| **Cleartext subject line** | The message subject is stored in plaintext. This is intentional for routing UX but leaks metadata. A future version may encrypt it. |
| **P-256 vs X25519 naming** | The frontend uses P-256 (NIST) via WebCrypto, not Curve25519/X25519. While X25519/Ed25519 is now supported in recent browsers (Chrome 111+, Firefox 119+, Safari 17+), P-256 was chosen for broader compatibility including older browser versions still in common use. The method was named `generateX25519KeyPair()` but has been renamed to `generateECDHKeyPair()` to accurately reflect the underlying curve. Both provide ~128-bit security for ECDH. |
| **Fixed blind token salt** | `'weaponmail-blind-token-salt-v1'` is a well-known constant. See Blind Token section above. |
| **SHA-256 login hash ⚠️ Must Fix Before Production** | The login hash is single-iteration SHA-256 — not memory-hard. Offline cracking of leaked hashes is feasible without additional server-side password hashing. A future version should add bcrypt/scrypt on the server side. |
| **No key rotation** | There is currently no key rotation mechanism. Compromising a user's long-term private key exposes all stored message keys (though past message bodies require the ephemeral keys which are discarded). Key rotation is a planned future improvement. |
| **ScyllaDB search_tokens** | Full keyword-token search requires SASI indexes or a separate lookup table. The current schema uses a `message_search_index` table; SASI is not universally available. |

---

## Key Rotation Strategy

Key rotation is **not yet implemented**. The current design stores a single long-term key pair per user:
- `publicKey` — stored server-side in plaintext (needed for senders)
- `encryptedPrivateKey` — AES-GCM encrypted with the master key, stored server-side

**Future rotation plan**:
1. Generate a new key pair client-side
2. Re-wrap all existing `messageKey` fields with the new private key (client-side batch operation)
3. Upload the new `encryptedPrivateKey` and new `publicKey` to the server atomically
4. Invalidate the old key pair

Until rotation is implemented, a compromised long-term private key exposes the ability to decrypt future messages and unwrap stored `messageKey` fields.

---

## Technology Choices

| Component | Technology | Reason |
|---|---|---|
| Backend ECDH (tests) | BouncyCastle `bcprov-jdk18on` | JDK does not include X25519 key pair generation; BouncyCastle provides `X25519KeyPairGenerator` |
| Frontend ECDH | WebCrypto P-256 | Native browser API — no external library, no WASM cost for key operations |
| Symmetric encryption | AES-256-GCM | AEAD — provides both confidentiality and integrity in one pass |
| KDF (interactive) | Argon2id | Memory-hard, RFC 9106 recommended for password hashing |
| KDF (fallback) | PBKDF2-SHA256 | WebCrypto native — zero external deps; 600 000 iterations per OWASP 2023 |
| Framework | Spring Boot 4.x WebFlux | Non-blocking reactive stack; all DB calls return `Mono`/`Flux` |
| Database | ScyllaDB (Cassandra-compatible) | High-throughput distributed storage; blind token index via secondary index |
