---
layout: default
title: CAS - Trusted Device Multifactor Authentication
category: Multifactor Authentication
---

{% include variables.html %}

# Redis Device Storage - Multifactor Authentication Trusted Device/Browser

User decisions may also be kept inside a Redis instance.

Support is provided via the following module:

{% include_cached casmodule.html group="org.apereo.cas" module="cas-server-support-trusted-mfa-redis" %}

## Record Index Schema Cutover

CAS-IDP fork releases store each trusted-device decision under its principal's
account-security slot and maintain a per-principal record index. The first
deployment of `record-index-schema-v3` inventories both legacy buckets and
current-format records before it publishes the global schema READY state. A
lease allows one current node to perform that inventory while its peers wait;
READY must be produced by CAS and must never be created or restored separately
from the records and index state it represents. Versioned `record-index-v3`,
`record-index-state-v3`, and `record-index-lease-v3` keys prevent an older
schema marker from being accepted as proof of the v3 write-token inventory.

This first adoption requires a full-stop cutover. An old CAS writer only knows
the legacy bucket layout. A legacy write during adoption can land behind the
inventory scan cursor and escape the READY inventory; a write after READY cannot
maintain the current index or honor its terminal fence. Zero old writers may be
active from before the adopter starts, throughout inventory, or after READY.
Rolling, canary, and mixed-version upgrades against the same writable Redis
authority are therefore unsupported.

### Preflight

1. Identify every CAS pod, background job, administrative tool, and disaster
   recovery process that can write the trusted-MFA Redis authority. Include
   delayed retries and any controller capable of recreating an old pod.
2. Disable old-deployment autoscaling and automatic restart. Validate the new
   release and schema adoption against a recent restored copy, including the
   largest legacy principal, before the outage.
3. Confirm that all new nodes use the same writable Redis primary or Sentinel
   authority and that Redis has enough memory and latency headroom for the
   inventory. Prepare and test restoration of a consistent whole-dataset
   snapshot; a marker-only backup is not sufficient.

### Cutover

1. Drain login traffic and pause trusted-device administration and cleanup.
   Stop every old CAS writer and verify that no old process or connection can
   resume writes.
2. Take the final quiesced Redis snapshot. Keep it immutable for the rollback
   window.
3. Start one current-version CAS node with user ingress closed. It acquires the
   adoption lease, performs the existing-principal inventory, and publishes
   READY only after that inventory completes. Treat a timeout, lost lease,
   capacity limit, malformed record, or owner mismatch as a failed cutover; do
   not manufacture READY or weaken the check.
4. After READY, start the remaining current-version nodes. Exercise login lookup
   and removal for representative legacy and current principals, observe their
   bounded per-principal rebuilds, and only then reopen traffic. Do not allow an
   old pod to rejoin after this point.

### Rollback

1. Close traffic and stop every current-version writer. Never start an old node
   beside a current node while both can reach the same writable dataset.
2. Restore the complete quiesced pre-cutover snapshot, or switch a blue-green
   deployment back to an isolated old dataset. Do not merely delete READY or
   restore selected state/index keys: current nodes may already have migrated a
   legacy bucket or written current-format records that an old node cannot
   safely manage.
3. Verify the restored dataset, then start only old-version nodes and reopen
   traffic. The restore loses trusted-device decisions created after the
   snapshot. If that is unacceptable, leave traffic closed and roll forward
   with a corrected current release instead.

## Scan Boundary

Steady-state save, principal login lookup, and removal by trusted-record key use
the per-principal index and do not perform a Redis database-wide `SCAN`. When a
principal is first accessed after adoption, CAS may use bounded scans restricted
to that principal's current and legacy key patterns to rebuild and migrate its
index. The number of matching records is bounded, but Redis `SCAN MATCH` can
still traverse the database cursor; treat this as transitional migration work,
not as a constant-time lookup. Pre-warm known legacy principals before reopening
peak traffic and alert on rebuild latency.

A global trusted-MFA namespace `SCAN` is reserved for the one-time schema
adoption and explicit administrative maintenance: full inventory/date queries,
record lookup by numeric ID, and expiration cleanup. Those operations are not
the steady authentication path and should be scheduled and monitored as
keyspace-sized work. Normal login and record-key removal remain index-bounded
after READY.

## Concurrency and Capacity Boundary

Each principal and each opaque trusted-record coordinate is bounded to 256
indexed candidates. A save first reserves a raw-principal-free pending locator
hint, writes the principal-slot authority with a unique write token, and then
commits the locator hint. A rejected or transport-ambiguous commit retains the
pending hint until an exact token-bound rollback is known to have completed or
the record expires. Removal drains short-lived publication intents and consumes
both committed and pending hints, so a writer crash cannot make a written
authority value undiscoverable. Capacity rejection occurs before the authority
write and counts the unique union of committed and pending candidates.

The locator is an index hint, never authentication authority. Every candidate
is re-read from its principal-owned authority slot and checked against the
terminal account-deletion fence, principal digest, record identifier, opaque
record-key digest, authority key, and expiry. Indexed authority reads also bind
each serialized value to its unique write token. Locator keys and members contain no
raw principal or raw record key. Pending crash-recovery metadata is
pseudonymous and may remain until the trusted record's bounded expiry; account
erasure authorization does not depend on that metadata.

All Lua scripts access only keys declared in `KEYS` and every multi-key script
uses one Redis Cluster hash slot. Per-principal reads use a bounded two-phase
snapshot/final-validation protocol so member swaps, expiry, and terminal fences
between phases cause retry or fail closed rather than a partial read.

## Redis Durability Boundary

Use one writable primary (directly or through Sentinel), disable replica reads,
use `noeviction`, and monitor persistence, replication lag, failover, command
latency, memory headroom, and the bounded index limits. AOF, an appropriately
strict `appendfsync` policy, and `min-replicas-to-write` reduce acknowledged-
write loss but Redis asynchronous replication does not prove that a recent
authority write, revocation tombstone, or terminal fence survives every
primary-loss event. Deployments requiring mathematically strict
non-resurrection across infrastructure loss need a CP/durable source of truth
and reconciliation in addition to this Redis repository. Validate the chosen
RPO/RTO with forced-primary-loss and whole-dataset restore exercises before
production approval.

{% include_cached casproperties.html properties="cas.authn.mfa.trusted.redis" %}
