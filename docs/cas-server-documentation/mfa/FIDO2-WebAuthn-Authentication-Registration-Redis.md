---
layout: default
title: CAS - FIDO2 WebAuthn Multifactor Authentication
category: Multifactor Authentication
---

{% include variables.html %}

# Redis FIDO2 WebAuthn Multifactor Registration

Device registrations may be kept inside a Redis database instance by including the following module in the WAR overlay:

{% include_cached casmodule.html group="org.apereo.cas" module="cas-server-support-webauthn-redis" %}

## Locator Schema Cutover

CAS-IDP fork releases keep each principal's encrypted WebAuthn registrations in
the principal account-security slot. Raw-principal-free secondary locators map
credential identifiers and user handles to possible principal digests. Schema
v3 also stores an independent write token beside every current authority value;
the token makes a delete-and-recreate operation distinguishable even when the
serialized registration bytes are identical.

The first v3 node acquires a bounded lease and streams the WebAuthn authority
namespace to migrate legacy records and rebuild locators. It publishes the v3
READY marker only after the inventory completes. Authentication lookup never
falls back to a request-time full scan when READY is missing: it fails closed.
READY is proof about the corresponding authority, write-token, and locator
state and must not be created or restored independently.

Adoption requires a full-stop cutover. Older nodes cannot maintain v3 locators
or write tokens and do not honor the terminal account-deletion fence. A legacy
write during the inventory can also land behind the scan cursor. Rolling,
canary, and mixed-version writers against the same writable Redis dataset are
therefore unsupported.

### Preflight and Cutover

1. Inventory every CAS node, administrative tool, background job, retry queue,
   and disaster-recovery process that can write WebAuthn Redis data. Disable
   controllers that could recreate an old writer.
2. Validate the migration on a recent restored copy, including the largest
   authority namespace and the most-shared credential/user-handle coordinate.
   Confirm memory and command-latency headroom for the inventory.
3. Drain authentication and registration traffic, stop every old writer, and
   take a final quiesced whole-dataset snapshot.
4. Start one current node with user ingress closed. Treat a malformed record,
   lost lease, locator capacity rejection, timeout, or owner mismatch as a
   failed cutover; never manufacture READY or weaken validation.
5. After READY exists, start the remaining current nodes. Exercise username,
   credential-id, and user-handle lookup plus add, counter update, and removal
   before reopening traffic. Never allow an old writer to rejoin.

To roll back, close ingress, stop every current writer, and restore the complete
quiesced pre-cutover snapshot (or switch to an isolated blue-green old
dataset). Deleting READY or selectively restoring records is not a rollback:
current nodes may have removed legacy keys or written state that old nodes
cannot safely manage.

## Lookup, Concurrency, and Capacity Boundaries

Steady-state credential-id and user-handle authentication uses a bounded
locator read and never scans the authority keyspace. Locator members are hints,
not authentication authority. Every candidate is re-read from its
principal-owned slot and checked against the terminal fence, stored owner,
principal digest, and requested credential coordinate before it can
authenticate. Stale hints are removed only after publication-intent and
authority rechecks, so concurrent publication cannot turn cleanup into a lost
credential.

Each locator coordinate is limited to 256 principal candidates. Each
coordinate/principal publication-intent set is limited to 256 live writer
tokens, and intents expire after a short bounded interval. Capacity and corrupt
type/member states fail closed before unbounded member materialization. Keys
and members contain SHA-256 digests rather than raw principals, credential IDs,
or user handles; operators must still treat them as security-sensitive
pseudonymous data.

All authority mutations use a bounded compare-and-set loop. The authority
value and its independent fresh write token are read and replaced in one
principal-slot Lua operation. CAS compares both, preventing lost updates,
signature-counter regression, and same-byte ABA acceptance. Publication hints
are reserved before the cross-slot authority CAS and reconciled afterward.
Terminal account erasure deletes the current value, its write token, and the
legacy value under the same durable closure token.

Every multi-key Lua script uses declared keys in one Redis Cluster hash slot.
The schema READY/lease keys share a schema slot; each locator and its
publication intent share a coordinate slot; and authority data, write token,
and terminal fence share a principal slot. These are separate atomicity
domains, joined by publication intents and authority revalidation rather than
an unsafe cross-slot transaction.

## Redis Durability Boundary

Use primary-routed reads and writes, `noeviction`, authenticated TLS, and a
dedicated capacity budget. Monitor persistence health, replication lag,
failover, memory headroom, command latency, rebuild duration, capacity
rejections, and fence failures. Load-test hot shared coordinates and migration
startup at production cardinality; bounded work is not evidence that the
chosen limits or Redis shard are fast enough for the target workload.

Back up and restore the entire consistent dataset, including legacy/current
authority values, write tokens, terminal fences, locator candidates,
publication intents, and READY/lease state. A record-only restore with a stale
READY marker can make a credential undiscoverable; a token-only or fence-only
restore fails closed. Validate forced-primary-loss and whole-dataset restore
against the required RPO/RTO. Redis asynchronous replication cannot by itself
prove zero acknowledged-write loss; deployments requiring strict
non-resurrection across infrastructure loss need a CP/durable source of truth
and reconciliation in addition to this repository.

{% include_cached casproperties.html properties="cas.authn.mfa.web-authn.redis" %}
