CREATE KEYSPACE IF NOT EXISTS weaponmail 
WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1};

CREATE TABLE IF NOT EXISTS weaponmail.messages (
    recipient text,
    thread_id uuid,
    id timeuuid,
    subject text,
    encrypted_body text,
    message_key text,
    sender_public_key text,
    sender_blind_token text,
    PRIMARY KEY (recipient, thread_id, id)
) WITH CLUSTERING ORDER BY (thread_id ASC, id DESC);
CREATE INDEX IF NOT EXISTS idx_sender_token ON weaponmail.messages (sender_blind_token);



