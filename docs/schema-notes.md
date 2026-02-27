# ScyllaDB Schema Notes

## Secondary Indexes for Blind Search

### `search_tokens` Index

The `search_tokens` column is a `set<text>` containing HMAC-SHA256 blind tokens for
keyword search (subject words and body keywords). To support efficient `CONTAINS` queries
on this column, a secondary index must be created by the DBA at deployment time:

```cql
CREATE INDEX ON messages (search_tokens);
```

> **Note:** This index is a **manual DBA operation** for production deployments.
> It is **not** added automatically by application startup code.
> ScyllaDB supports `CONTAINS` queries on `set` columns when a secondary index exists.

### Existing Indexes

The `sender_blind_token` column is already indexed via the Spring Data Cassandra
`findAllByKeyRecipientAndSenderBlindToken` repository method, which relies on
Cassandra's query-based routing (partition key filtering).

## Attachments Column

The `attachments` column is a `list<text>` where each entry has the format:

```
<filename>:<base64-ciphertext>
```

The attachment binary is encrypted client-side with the same ECDH-derived AES-GCM key
as the message body. The server stores and returns these as opaque strings — it never
has access to the plaintext attachment content.

Schema addition (if upgrading an existing cluster):

```cql
ALTER TABLE messages ADD attachments list<text>;
```
