CREATE KEYSPACE IF NOT EXISTS weaponmail 
WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1};

CREATE TABLE IF NOT EXISTS weaponmail.messages (
    recipient text,           -- Partition Key (All user's mail stays together)
    id timeuuid,              -- Clustering Key (Sorted by time automatically)
    subject text,
    encrypted_body text,
    message_key text,
    sender_public_key text,
    PRIMARY KEY (recipient, id)
) WITH CLUSTERING ORDER BY (id DESC);
