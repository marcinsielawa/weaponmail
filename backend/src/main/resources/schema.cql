CREATE KEYSPACE IF NOT EXISTS weaponmail 
WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1};

-- Accounts table
CREATE TABLE IF NOT EXISTS weaponmail.accounts (
    username text PRIMARY KEY,
    login_hash text,
    public_key text,
    encrypted_private_key text,
    password_salt text,
    created_at bigint
);

-- Messages table (extended with sealed flag, encrypted_sender, and search_tokens)
CREATE TABLE IF NOT EXISTS weaponmail.messages (
    recipient text,
    thread_id uuid,
    id timeuuid,
    subject text,
    encrypted_body text,
    message_key text,
    sender_public_key text,
    sender_blind_token text,
    -- Encrypted sender address (encrypted to recipient's public key)
    -- Client decrypts this to display the sender in the inbox, server never sees it.
    encrypted_sender text,
    -- HMAC-SHA256 keyword tokens for blind search (set of Base64 strings).
    -- Derived client-side using a key derived from the master key.
    -- The server stores these as opaque tokens and matches them blindly.
    search_tokens set<text>,
    -- Sealed messages are excluded from search and blind-token lookups.
    -- They can only be accessed via direct recipient+thread+id lookup.
    sealed boolean,
    PRIMARY KEY (recipient, thread_id, id)
) WITH CLUSTERING ORDER BY (thread_id ASC, id DESC);

CREATE INDEX IF NOT EXISTS idx_sender_token ON weaponmail.messages (sender_blind_token);
-- Note: search_tokens requires SASI or a separate table for efficient querying.
-- For the demo, we use a lookup table pattern (see MessageSearchToken table below).

-- Blind keyword search lookup table
-- Each row is one (recipient, token) → set of message IDs that contain that keyword.
-- This pattern allows efficient O(1) lookup without exposing keywords to the server.
CREATE TABLE IF NOT EXISTS weaponmail.message_search_index (
    recipient text,
    search_token text,
    message_id timeuuid,
    thread_id uuid,
    PRIMARY KEY ((recipient, search_token), message_id)
) WITH CLUSTERING ORDER BY (message_id DESC);