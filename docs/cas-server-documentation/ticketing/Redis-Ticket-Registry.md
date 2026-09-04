---
layout: default
title: CAS - Redis Ticket Registry
category: Ticketing
---

{% include variables.html %}

# Redis Ticket Registry

Redis integration is enabled by including the following dependency in the WAR overlay:

{% include_cached casmodule.html group="org.apereo.cas" module="cas-server-support-redis-ticket-registry" %}

This registry stores tickets in one or more [Redis](https://redis.io/) instances. CAS presents and uses Redis as a
key/value store that accepts `String` keys and CAS ticket documents as values. The key is started with `CAS_TICKET:`.

The Redis ticket registry supports Redis Sentinel, which provides high availability for Redis. In 
practical terms this means that using Sentinel you can create a Redis deployment that resists 
without human intervention to certain kind of failures. Redis Sentinel also provides other 
collateral tasks such as monitoring, notifications and acts as a configuration provider for clients.

The ticket registry's atomic key schema supports Redis single-primary and Sentinel deployments.
Redis Cluster is not supported. Ticket hashes, Spring Data keyspace sets, SSO session indexes, and
principal ticket indexes intentionally use distinct keys that do not share a Redis Cluster hash slot;
CAS fails startup when cluster nodes are configured instead of allowing a later `CROSSSLOT` failure or
a partially maintained security index.

## Principal Ticket Index

Every ticket document with an authentication principal is recorded in a
`CAS_PRINCIPAL_TICKET:<mapped-principal>` sorted set. The mapped value is a stable,
domain-separated SHA-512 digest of the exact principal identifier. Case and surrounding whitespace are
not folded because generic CAS deployments may treat them as identity-significant. Input is limited to
1,024 UTF-16 code units before hashing to bound work on untrusted identifiers. The digest never depends on optional
ticket payload encryption, so disabling that feature does not place a raw username in principal ticket,
session, or mutation-fence keys. This includes TGT, PGT, ST, PT, OAuth/OIDC,
and module-defined authentication-aware ticket types. A member is the complete authoritative Redis
ticket key and its score is the ticket's absolute expiration in milliseconds. Ticket writes and updates
maintain the ticket hash, Spring Data keyspace member, principal ticket index, and legacy TGT/PGT session
index in one Lua linearization point. Single-ticket deletes and account-scoped delete batches atomically
remove the same metadata. Index expiration follows its latest member; expired members are pruned using
Redis server time.

Account-scoped deletion reads only this index in bounded batches. It checks the principal stored in each
ticket hash again immediately before unlinking the ticket, so a concurrently reassigned key is not deleted
for its old principal. Missing tickets clean stale metadata, while wrong Redis types or a ticket hash with
no principal fail closed without consuming the index member. There is no ticket-keyspace scan fallback.

On the first upgrade to this index schema, one CAS node acquires a renewable Redis lease and performs a
one-time, bounded rebuild of existing ticket hashes. A durable schema marker enables account-scoped
deletion only after the rebuild completes. Other nodes remain fail-closed until that marker exists, and a
crashed owner is replaced by a bounded background retry after its lease expires; lease ownership and retry
failures are logged. A principal-bearing ticket without an expiration is treated as corrupt: rebuild stops
without publishing READY instead of silently producing an incomplete index. Registry-wide deletion
acquires a renewable mutation fence, removes the readiness marker, and rejects overlapping ticket writes
until ticket hashes and indexes have been cleared and READY is atomically republished. Every mutating
rebuild or registry-deletion page verifies its exact lease token inside the same Lua operation before it
scans or unlinks keys; renewal after a page is only a liveness extension, not the ownership check. Every
account-deletion load and delete page likewise rechecks the exact READY schema and absence of the global
mutation fence atomically, including an empty terminal page, so a registry-wide cutover cannot race an
account deletion into reporting false completion. Use a full-stop
upgrade: an older CAS node that is allowed to write after the
marker is committed cannot maintain the new index or honor the deletion fence. Custom
`RedisTicketRegistryWriteExecutor` implementations must atomically reject writes when the supplied
`mutationFenceKey` or `principalMutationFenceKey` exists and apply both the `principalIndex` and
`principalSessionIndex` coordinates provided in each write command; invoking the supplied default
persistence operation already does all four. The principal-scoped check is unconditional and does not
depend on whether a write carries a managed issuance context. For generation-aware idempotent replay,
repair the all-ticket principal index, but do not reapply a
`MOST_RECENT` session mutation for an older replay; doing so would incorrectly make the old session recent.
An `ALL` session mutation is safe to replay. Prune expired `ALL` members before adding the current member,
then refresh the ZSET expiration without another time-based prune. Session scores truncate expiration
milliseconds to whole seconds, so only scores through `nowSecond - 1` are certainly expired. Pruning the
current or next whole second during a write, old-principal refresh, or inventory cleanup can discard a
still-valid short-lived session.

CAS also publishes a `redisPrincipalTicketMutationFence` collaboration bean for account lifecycle
workers. Its API accepts a raw principal id and applies the same exact-identity Redis principal codec internally;
`keyForPrincipal` and each write command expose the exact Redis key needed by a custom atomic writer.
Temporary acquisition is token-owned and leased: replaying the same token renews it, a different token
fails, and release removes only a matching temporary fence. A terminal acquisition is permanent, can
atomically promote a temporary fence owned by the same token, and cannot be removed by the temporary
release operation. Terminal fences are intentionally outside ticket/index keyspaces and survive
registry-wide ticket deletion. Principal-scoped ticket deletion remains allowed while either fence mode is
present, so a lifecycle worker can fence first and then drain authoritative tickets without globally
blocking unrelated accounts.

During an upgrade, reads and account-scoped deletion also recognize the previous ticket-registry
principal mapping for tickets and session indexes that were written before this codec existed. New writes
never create those legacy keys. The compatibility path can be removed only after the maximum pre-upgrade
ticket lifetime has elapsed or the ticket Redis dataset has been deliberately drained. This bridge is
sufficient for deployments whose principal provider emits one stable representation, including the CAS IDP
overlay's canonical UUID identifiers; it intentionally does not merge case-distinct generic CAS identities.

The first deployment that introduces the codec, rebuilt index, and principal mutation fences must be a
full-stop/recreate cutover: stop every old CAS writer, deploy only current writers, complete READY rebuild,
and only then reopen traffic.
An older writer does not know how to check this namespace and can otherwise write through a fence during
a mixed-version rollout.
When the same release first introduces trusted-MFA `record-index-schema-v3` and the WebAuthn v3
locator/write-token protocol, perform one coordinated full-stop for all Redis authorities and keep every
old CAS writer stopped until every inventory is READY. The trusted-MFA
[Redis storage guide](../mfa/Multifactor-TrustedDevice-Authentication-Storage-Redis.html) and WebAuthn
[Redis registration guide](../mfa/FIDO2-WebAuthn-Authentication-Registration-Redis.html) define their
preflight, cutover, rollback, and scan boundaries.

Code that deletes a managed ticket hash directly, outside `RedisTicketRegistry`, must remove the complete
ticket-key member from `principalIndex.redisKeyPrefix() + storedPrincipal` in the same Lua operation. A
TGT/PGT deletion must likewise remove the serialized session member. Relying on a future account deletion
to drain a missing-hash entry is only a self-healing safety net; a long-lived ticket score can otherwise
retain stale metadata for years.

Back up and restore ticket hashes, principal ticket indexes, and index metadata as one consistent Redis
dataset. Restoring a `READY` marker without its complete matching index can make an account appear to have
no tickets. If consistency is in doubt, stop every CAS writer, remove the `READY` marker, and let a current
CAS node rebuild before accepting traffic. Never create or restore the marker by itself, and never rebuild
while an older writer is active.

## Configuration

{% include_cached casproperties.html properties="cas.ticket.registry.redis" %}
  
## Indexing & Search

See [this guide](Redis-Ticket-Registry-RediSearch.html) for more information.

## Caching & Messaging

The Redis ticket registry layers an in-memory cache on top of Redis to assist with performance, particularly
when it comes to fetching ticket objects from Redis using `SCAN` or `KEYS` operations that execute pattern matching.
This cache is specific and isolated to the CAS server node's memory, and is able to clean up after itself with a dedicated
expiration policy that is constructed off of the ticket's expiration policy. Each cache inside an individual CAS server node
will attempt to synchronize ticket changes and updates with other CAS server nodes via a message-based mechanism backed by 
Redis itself. Note that you can always entirely disable the caching mechanism by forcing its maximum capacity to be at zero
via dedicated CAS settings.

{% include_cached casproperties.html properties="cas.ticket.registry.redis.cache" %}

### Actuator Endpoints

The following endpoints are provided by CAS:

{% include_cached actuators.html endpoints="redisTicketsCache" %}
  
### Design & Performance

The Redis ticket registry treats Redis as the shared source of truth for CAS tickets, while each 
CAS node may keep a local in-memory cache as a first-level optimization. The local cache is per-node 
and is intended to reduce Redis reads and ticket deserialization for hot tickets. It should not be 
treated as authoritative. Ticket lookups may be served from the local cache, but ticket lifecycle 
operations still need to keep Redis and all node-local caches coherent.

Cache keys are derived from the Redis ticket key format, not simply from the clear 
ticket id in all cases. This matters when registry cryptography is enabled. In that mode, ticket 
identifiers and principal identifiers are digested before being used in Redis keys, so the local cache 
key for a ticket is also the digested form. Any cache invalidation mechanism must use the same canonical 
cache key that the registry uses for reads and writes. Invalidating by the clear ticket id will miss 
encrypted/digested cache entries and can leave stale tickets alive on other nodes.

Cluster cache coherence is handled through Redis-backed pub/sub messages. When one CAS node adds,
updates, deletes, or clears tickets, it publishes a notification. Other CAS nodes receive that
notification and invalidate their local cache. Nodes should ignore their own messages because the local
registry operation has already invalidated its entry. The cache is populated on an authoritative read,
not by a write-through put: this prevents an in-flight write tail from repopulating a local cache after a
concurrent registry-wide delete has completed. For deletes,
the notification does not need to carry the full ticket object; it only needs enough information 
to identify the local cache entry, such as the Redis key or derived cache key. This avoids 
unnecessary Redis fetches, deserialization, and decryption during delete-heavy operations.

From a performance perspective, the important distinction is between operations that need 
the ticket body and operations that only need to remove state. Add and update messages naturally 
carry a ticket because peer caches may be populated with that object. Delete messages should avoid 
materializing the ticket when the registry already knows the Redis key being removed. Bulk user/session 
deletion paths are especially sensitive: scanning Redis, fetching each ticket, deserializing it, 
and decrypting it just to publish a cache invalidation can be very expensive. The principal ticket
index avoids that global scan. CAS reads only bounded index pages, unlinks matching Redis keys,
invalidates the local cache by canonical key, and publishes delete notifications by key.

There are several operational caveats. Redis pub/sub is not durable; a node that is down, 
disconnected, or misconfigured when a message is published can miss the notification and retain 
stale local cache entries until expiration or manual cache clearing. CAS node queue identifiers 
must be unique per node, or left unset so they are generated uniquely; if multiple nodes share 
the same identifier, they may incorrectly treat each other’s notifications as self-published messages and 
ignore them. Administrative logout cannot remove a user’s browser cookie directly, so correctness depends 
on the server-side ticket deletion being authoritative across Redis and all local caches. For highly 
conservative deployments, disabling the local cache or setting its size to zero trades performance 
for simpler consistency semantics. In particular, the Redis Lua operations provide atomic authoritative
revocation, but a concurrent read can obtain a ticket immediately before deletion and finish its local
cache put after invalidation. Deployments requiring strict account-revocation semantics must set the Redis
ticket-registry cache size to zero; pub/sub plus a nonzero near cache is best-effort coherence, not a durable
revocation fence.

Deployments that require strict account revocation or complete SLO session inventory must also configure
`cas.ticket.registry.redis.read-from=UPSTREAM`. Schema readiness, registry-wide deletion, and principal-index
mutation are always routed to the Redis primary, but ordinary ticket and session inventory reads honor the
configured read preference. `REPLICA`, `REPLICAPREFERRED`, and other replica-reading modes can therefore
observe replication lag and are suitable only when eventual consistency is acceptable for those reads.

Principal-index expiration and Spring Data keyspace-set cleanup are separate concerns. Index maintenance
prunes expired ZSET members using Redis server time, and the index key expires with its latest member.
Natural ticket expiration is not an account-deletion batch and therefore does not promise that this index
path will remove an already-expired ticket's Spring Data keyspace member.

## Eviction Policy

Redis manages the internal eviction policy of cached objects via its time-alive settings.
The timeout is the ticket's `timeToLive` value. So you need to ensure the cache is alive long enough to support the
individual expiration policy of tickets, and let CAS clean the tickets as part of its own cleaner if necessary.

Redis removes expired keys in two ways. Passive expiration happens when CAS accesses a 
key and Redis notices that its TTL has elapsed; the key is deleted before the command proceeds. 
Active expiration runs periodically in the background: Redis samples keys that have TTLs, deletes 
the ones that are already expired, and repeats this work within a CPU-time budget. This means 
expired keys are usually removed quickly, but deletion is not a continuous full scan of the keyspace.

## Ticket Registry Locking

This ticket registry implementation automatically supports [distributed locking](../ticketing/Ticket-Registry-Locking.html).
The schemas and structures that track locking operations should be automatically created by CAS using
[Spring Integration](https://spring.io/projects/spring-integration) Redis support.

CAS-IDP fork builds use a versioned, domain-separated SHA-256 digest for the
ticket portion of Redis lock keys so raw TGT and ST identifiers are not exposed
in the Redis keyspace. This changes the distributed-lock namespace. Do not run
a raw-lock-key build and a digest-lock-key build against the same writable
ticket Redis during a rolling replacement: the two versions would not contend
for the same lock, including the lock that protects single-use service-ticket
validation. Stop and drain every old node before starting the new version, or
use an isolated ticket Redis for a blue-green cutover.
