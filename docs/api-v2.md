# nftbk 2.0 API and migration

Version 2 separates an NFT snapshot from the outputs that protect it. An archive
can expire or be deleted while an IPFS pin set keeps running. Creating another
output reuses the snapshot's observations and retained bytes. Creating another
snapshot observes the NFTs again and gets a new UUID.

This implements the resource separation in [issue 88][architecture-issue] and
CAIP-2 adoption in [issue 42][caip-issue]. Deploy the Partal v2 client together
with this server. There are no `/v1` compatibility routes.

## Identity and requests

NFT identities contain three strings:

```json
{
  "chain_id": "eip155:1",
  "contract_address": "0x00000000000000000000000000000000000000ab",
  "token_id": "42"
}
```

`chain_id` follows [CAIP-2][caip2]. EVM references are positive decimal chain
numbers. [Tezos references][tezos] preserve the case of the network ID, for
example `tezos:NetXdQprcVkpaWU`. EVM addresses are normalized to lowercase;
Tezos addresses remain case sensitive. Decimal token IDs remain strings so
that JavaScript cannot truncate large identifiers. Selection order and
repeated NFTs do not change a normalized specification.

RPC configuration keys and token configuration keys use quoted CAIP-2 IDs.
Known 1.x configuration aliases are normalized for the transition. Unknown
aliases require an explicit mapping before upgrading. New HTTP requests reject
aliases such as `ethereum` and reject unknown JSON fields.

All public resource IDs are UUIDs. A JWT principal is the pair `(iss, sub)`;
subjects from different issuers cannot see one another's resources. The static
admin token has a separate local principal. A server with no authentication
configured has one explicitly shared local principal.

## Resources

| Resource | Collection | Meaning |
| --- | --- | --- |
| Backup | `/v2/backups` | Snapshot and summary of its outputs |
| Item | `/v2/backups/{id}/items` | Per-NFT observation and asset outcomes |
| Manifest | `/v2/backups/{id}/manifest` | Sealed snapshot inventory |
| Archive | `/v2/archives` | ZIP or tar.gz artifact and retention |
| Pin set | `/v2/pin-sets` | IPFS coverage for one snapshot |
| Pin | `/v2/pins` | Observed provider pin with owned NFT references |
| Quote | `/v2/quotes` | Expiring price and cached metadata plan |
| Operation | `/v2/operations` | Durable work, state and failure |
| Attempt | `/v2/operations/{id}/attempts` | Execution and retry history |

Top-level and item collection GETs return
`{"data": [], "next_cursor": null}`. `limit` is 1–100;
pass `next_cursor` back as `cursor`. Ordering is descending by creation time
and UUID. Cursors are opaque and independent of offsets. Item filters include
`chain_id`, `contract_address`, `token_id`, `state` and `ipfs_only`. Pin filters
include NFT identity, CID, state and an owned `pin_set_id`. Filtering happens
before pagination. Archives and pin sets can be filtered by `backup_id`.

Resource representations include links to their own URI and related work.
Individual GETs support ETags and `If-None-Match`. Errors use
[RFC 9457 problem details][problems] with stable `urn:nftbk:problem:*` types.
The x402 challenge and verification errors retain their protocol JSON shape.
An unavailable or full work queue returns `503` with `Retry-After`.

OpenAPI is at `/v2/openapi.json`; the interactive reference is at
`/v2/swagger-ui`.

## Create a snapshot

```http
POST /v2/backups
Authorization: Bearer <token>
Content-Type: application/json
Idempotency-Key: <one-key-per-user-action>

{
  "nfts": [{
    "chain_id": "eip155:1",
    "contract_address": "0x00000000000000000000000000000000000000ab",
    "token_id": "42"
  }],
  "outputs": [
    {"type": "archive", "format": "zip"},
    {"type": "ipfs"}
  ]
}
```

Creation returns `201 Created`, a `Location` header and the resource in its
current state. Follow `operation_id` or poll the resource. Capture runs first;
archive and pin operations run independently after it seals. A partial snapshot
can produce a partial archive. Failures are recorded on individual items and
assets rather than hidden by a successful submission response.

Archive format is explicit: `zip` or `tar.gz`. Optional `retention_days`
defaults to the server's configured retention and cannot exceed it. Retention
starts when the artifact is published. Requests contain 1–1000 NFTs and 1–3
outputs; identical output specifications are deduplicated.

Use the same idempotency key for retries of the same action, including payment
retries. It returns the same resource without duplicating work. Reusing a key
with a different normalized payload returns `409`. A new key creates a fresh
snapshot, even for the same NFT selection. Paid creation requires a key; free
creation accepts one. Unpaid reservations are deleted after their quote expires.
There is no `force` flag or content-derived public ID.

## Add or remove outputs

```http
POST /v2/archives
Content-Type: application/json
Idempotency-Key: <new-key>

{"backup_id":"<snapshot-uuid>","format":"tar.gz","retention_days":2}
```

Create IPFS retention with `POST /v2/pin-sets` and
`{"backup_id":"<snapshot-uuid>"}`. These are new output resources with their
own operations. A pin-only snapshot might not retain downloadable media; adding
an archive then returns `409` and requires a fresh snapshot with an archive
output. Adding outputs never silently refetches and changes a sealed snapshot.

DELETE an archive or pin set at its own URI. DELETE a backup to remove all its
outputs and release its retained snapshot bytes. Deletion returns `202` and a
Location pointing to its operation. Repeated DELETE returns the same operation.
An active capture, output operation or uncertain payment must finish or be
reconciled first; the API returns `409` while it is active.

`deletion_requested_at` records intent; `deleted_at` is set only after cleanup
succeeds. Cleanup failures stay visible and retryable. Tombstones and operation
history remain available after physical cleanup. Expired archives return `410`
for content, and retention cleanup runs through durable deletion operations.

Pin-set counts have separate meanings:

- `requested_nft_count`: all NFTs in the snapshot.
- `eligible_nft_count`: NFTs with at least one IPFS asset.
- `protected_nft_count`: eligible NFTs whose IPFS assets are observed pinned at
  every provider account selected for that pin set.
- `skipped_nft_count`: NFTs without IPFS assets.

Provider acceptance alone does not mean protected. A mixed HTTP/IPFS selection
reports partial IPFS coverage. Pin sets share provider pins for the same CID
and account; removal unpins only when the last membership is gone. Provider
account identity includes the configured credential variable name, so two
accounts at the same URL do not share ownership accidentally. Keep that name
stable when rotating its secret.

## Quotes and payments

On a paid server, POST the same `nfts` and `outputs` specification to
`/v2/quotes`, then poll until `state` is `ready`. Pass `quote_id` in the
creation body. Prices use `amount_atomic`, `asset_decimals`, `asset_symbol`,
`asset_address` and CAIP-2 `chain_id`. A free server returns
`409 urn:nftbk:problem:pricing_unavailable` for quotes.

For an additional output, quote
`{"backup_id":"<uuid>","outputs":[{"type":"ipfs"}]}`. That quote belongs
only to that snapshot and output. NFT selection, output type, archive format,
retention, provider accounts and pricing policy are bound to the quote. An
expired quote or changed specification requires a new quote and creation key.

Quote workers retain original metadata bytes and their observation time.
Capture reuses that plan instead of fetching different metadata after payment.
Media sizes are estimates from HEAD responses; media can change before capture.
The quote is the accepted fixed charge, not a byte-for-byte guarantee of future
remote content. The existing x402 v1 facilitator protocol is retained; public
nftbk chain identifiers are CAIP-2 independently of protocol network names.

Payment intents, proof hashes and settlement requests are persisted before
calling the facilitator. No capture or output work starts before payment.
A paid replay returns the same resource and settlement receipt. Authorizations
cannot be attached to another request. If settlement is interrupted, its state
becomes `reconciliation_required`; the server refuses another charge.

Uncertain settlements require operator reconciliation with facilitator or
chain evidence. The server does not infer success from a timeout or blindly
resubmit a transfer. Preserve the payment row and its settlement request when
investigating. There is no public endpoint to override payment evidence.

## Downloads and retries

Authenticated GET or HEAD `/v2/archives/{id}/content` streams an archive.
POST `/v2/archives/{id}/download-links` issues a signed URL valid for ten
minutes. That URL supports repeated GETs, HEAD, ETags, single byte ranges and
`If-Range`, so browsers can resume downloads. Grants are scoped to the archive
and owner; the signing key is persisted across restarts. Archive deletion or
expiration still invalidates access.

POST `/v2/operations/{id}/attempts` retries a failed operation and returns
`201` with a readable attempt Location. An attempt has `requested_at`, an
optional `started_at`, `finished_at` and a structured failure. Failed capture
must be retried before dependent outputs. Transient provider polling resumes
the same attempt; a failed or abandoned worker creates a new attempt.

## Database and storage

PostgreSQL owns resource state, idempotency, payment intent and the work queue.
Workers claim short transactions with `FOR UPDATE SKIP LOCKED`, renew leases
and fence every checkpoint using a lease token. Restart recovery requeues
expired work. The queue admission limit counts pending operations, including
unpaid reservations; worker count is separate from connection-pool size.

```mermaid
erDiagram
    principals ||--o{ backups : owns
    backups ||--o{ backup_items : contains
    backup_items ||--o{ item_assets : observes
    backups ||--o{ archives : produces
    backups ||--o{ pin_sets : protects
    pin_sets ||--o{ pin_memberships : retains
    item_assets ||--o{ pin_memberships : references
    provider_pins ||--o{ pin_memberships : serves
    provider_instances ||--o{ provider_pins : hosts
    operations ||--o{ operation_attempts : executes
    quotes ||--o{ payments : prices
```

Composite foreign keys prevent outputs and pin memberships from referring to
another owner's snapshot or another item's asset. SQL read views assemble
response documents without making them the write model. Operational errors and
attempts remain separate from immutable observation data.

Blobs use SHA-256 addresses. Raw metadata preserves unmodeled fields and
original serialization. Manifests include metadata URI, observation time,
per-asset digest or CID, and individual outcomes. `block_reference` is nullable:
the current capture uses independent live RPC observations and does not claim
an atomic chain-wide block snapshot. Downloaded HTML can include processed
local dependencies; a digest identifies the retained bytes.

Files are published by atomic rename after synchronization. Active work and
unexpired quotes lease their blobs before publication. Garbage collection first
marks unreferenced blobs as deleting, removes the bytes, then records completion;
failed removal is retried. Publication and cleanup share per-digest filesystem
locks and cleanup rechecks the row after locking, so an old collector cannot
delete bytes reused by a new snapshot. Sources stay retained while their backup
exists, even after one archive expires. Delete the backup to release those sources.
All server instances must share the same volume with working POSIX file locks.
Keep PostgreSQL and the filesystem volume in coordinated backups. Staging
directories belonging to expired worker leases are removed automatically.

## Upgrade procedure

1. Stop the 1.x server and preserve a database backup and the complete archive
   volume. Apply the upgrade to a copy first.
2. Replace chain keys with CAIP-2 IDs in server and token configuration. Check
   custom chain aliases manually. Keep provider credential variable names
   stable and preserve their corresponding credentials.
3. Start the 2.0 binary against that database and the existing archive directory.
   Migration `002_api_v2.sql` appends the new schema and copies legacy resources;
   migration `001` and the 1.x tables remain unchanged. Legacy artifact paths
   remain usable. Legacy IDs are recorded internally as `legacy_task_id`.
   Unfinished legacy archives fail explicitly and require a new backup because
   their original snapshot bytes are unavailable.
4. Check migrated owners, archive availability and IPFS counts. With one JWT
   issuer, startup adopts legacy subjects into it. With multiple issuers, map
   `principals.issuer='legacy'` subjects to the correct issuer manually before
   serving traffic. Existing local admin records remain separate.
5. Deploy Partal's v2 proxy and client together with the server. Old clients and
   bookmarks using 1.x IDs or routes require replacement.
6. Verify creation, payment, downloads and deletion before retiring the rollback
   copy. Rolling back requires restoring both the database and archive volume;
   1.x cannot interpret changes made only to 2.0 resources.

Legacy records report `provenance: "legacy"`. Missing original metadata,
observation times, digests and per-item outcomes remain unknown instead of
being fabricated. Existing archive and IPFS lifecycles are migrated separately.
The old tables preserve data that cannot be assigned reliable provenance.

## Validation

`make all` runs formatting, sorting, clippy and unit tests. Unit tests mock
`Database`, RPCs and external HTTP calls. The opt-in PostgreSQL suite creates
and drops isolated databases under a dedicated validation database:

```sh
NFTBK_INTEGRATION_DATABASE_URL=postgresql://user:password@localhost/nftbk_v2 \
  SQLX_OFFLINE=true cargo test --test api_v2_postgres -- --ignored
```

It covers the legacy migration, raw metadata, independent output lifecycles,
resumable downloads, quote and payment binding, shared pin release, cleanup
failure history and fencing of abandoned workers. Partal's service and proxy
tests cover the wire contract and forwarded payment and download headers.

[architecture-issue]: https://github.com/0xmichalis/nftbk/issues/88
[caip-issue]: https://github.com/0xmichalis/nftbk/issues/42
[caip2]: https://standards.chainagnostic.org/CAIPs/caip-2
[tezos]: https://namespaces.chainagnostic.org/tezos/caip2
[problems]: https://www.rfc-editor.org/rfc/rfc9457.html
