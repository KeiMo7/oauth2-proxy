---
id: session_storage
title: Session Storage
---

Sessions allow a user's authentication to be tracked between multiple HTTP
requests to a service.

The OAuth2 Proxy uses a Cookie to track user sessions and will store the session
data in one of the available session storage backends.

At present the available backends are (as passed to `--session-store-type`):
- [cookie](#cookie-storage) (default)
- [redis](#redis-storage)
- [memory](#memory-storage)

### Cookie Storage

The Cookie storage backend is the default backend implementation and has
been used in the OAuth2 Proxy historically.

With the Cookie storage backend, all session information is stored in client
side cookies and transferred with each and every request.

The following should be known when using this implementation:
- Since all state is stored client side, this storage backend means that the OAuth2 Proxy is completely stateless
- Cookies are signed server side to prevent modification client-side
- It is mandatory to set a `cookie-secret` which will ensure data is encrypted within the cookie data.
- Since multiple requests can be made concurrently to the OAuth2 Proxy, this session implementation
cannot lock sessions and while updating and refreshing sessions, there can be conflicts which force
users to re-authenticate


### Redis Storage

The Redis Storage backend stores encrypted sessions in redis. Instead of sending all the information
back the client for storage, as in the [Cookie storage](#cookie-storage), a ticket is sent back
to the user as the cookie value instead.

A ticket is composed as the following:

`{CookieName}-{ticketID}.{secret}`

Where:

- The `CookieName` is the OAuth2 cookie name (_oauth2_proxy by default)
- The `ticketID` is a 128-bit random number, hex-encoded
- The `secret` is a 128-bit random number, base64url encoded (no padding). The secret is unique for every session.
- The pair of `{CookieName}-{ticketID}` comprises a ticket handle, and thus, the redis key
to which the session is stored. The encoded session is encrypted with the secret and stored
in redis via the `SETEX` command.

Encrypting every session uniquely protects the refresh/access/id tokens stored in the session from
disclosure. Additionally, the browser only has to send a short Cookie with every request and not the whole JWT, 
which can get quite big.

Two settings are used to configure the OAuth2 Proxy cookie lifetime:

    --cookie-refresh duration   refresh the cookie after this duration; 0 to disable
    --cookie-expire duration    expire timeframe for cookie     168h0m0s

The "cookie-expire" value should be equal to the lifetime of the Refresh-Token that is issued by the OAuth2 authorization server.
If it expires earlier and is deleted by the browser, OAuth2 Proxy cannot find the stored Refresh-Tokens in Redis and thus cannot start
the refresh flow to get a new Access-Token. If it is longer, it might be that the old Refresh-Token will be found in Redis but has already
expired.

The "cookie-refresh" value controls when OAuth2 Proxy tries to refresh an Access-Token. If it is set to "0", the
Access-Token will never be refreshed, even if it is already expired and a valid Refresh-Token is available. If set, OAuth2 Proxy will
refresh the Access-Token after this many seconds whether it is still valid or not. According to the official OAuth2.0 specification 
Access-Tokens are not required to follow a specific format. Therefore OAuth2 Proxy cannot check for any expiry date without an 
introspection endpoint. If an Access-Token expires and you have not set a corresponding "cookie-refresh" value, you will likely 
encounter expiry issues.

Caveat: It can happen that the Access-Token is valid for e.g. "1m" and a request happens after exactly "59s".
It would pass OAuth2 Proxy and be forwarded to the backend but is just expired when the backend tries to validate
it. This is especially relevant if the backend uses the JWT to make requests to other backends.
For this reason, it's advised to set the cookie-refresh a couple of seconds less than the Access-Token lifespan.

Recommended settings:

* cookie_refresh := Access-Token lifespan - 1m
* cookie_expire := Refresh-Token lifespan (i.e. Keycloak client_session_idle)

#### Usage

When using the redis store, specify `--session-store-type=redis` as well as the Redis connection URL, via
`--redis-connection-url=redis://host[:port][/db-number]`.

You may also configure the store for Redis Sentinel. In this case, you will want to use the
`--redis-use-sentinel=true` flag, as well as configure the flags `--redis-sentinel-master-name`
and `--redis-sentinel-connection-urls` appropriately.

Redis Cluster is available to be the backend store as well. To leverage it, you will need to set the
`--redis-use-cluster=true` flag, and configure the flags `--redis-cluster-connection-urls` appropriately.

Note that flags `--redis-use-sentinel=true` and `--redis-use-cluster=true` are mutually exclusive.

Note, if Redis timeout option is set to non-zero, the `--redis-connection-idle-timeout` 
must be less than [Redis timeout option](https://redis.io/docs/reference/clients/#client-timeouts). For example: if either redis.conf includes 
`timeout 15` or using `CONFIG SET timeout 15` the `--redis-connection-idle-timeout` must be at least `--redis-connection-idle-timeout=14`

### Memory Storage

The Memory storage backend (`--session-store-type=memory`) keeps encrypted
sessions in a per-process map. It uses the same ticket/cookie machinery as the
Redis backend (the `persistence.Manager`), so its cookie format is identical,
but:

- all state is lost when the process restarts;
- state is **not shared between replicas** — each process keeps its own map, so
  a session created on one replica is invisible to the others.

It is intended for single-replica deployments, local development and tests.
Multi-replica semantics require a shared backend (Redis).

### Strict session semantics

Historically every session-loading error — including a transient Redis timeout
— was treated the same as "not logged in": the session was cleared and the user
was redirected to sign in. A short Redis blip during a failover could therefore
sign out a whole fleet. Strict session semantics separate *store unavailability*
from *unauthenticated*, make logout reliable across replicas, and distinguish
natural expiry from deliberate revocation.

Strict semantics are **off by default** and enabled with
`--session-strict-semantics`. When disabled, behaviour is unchanged from
previous versions. The existing session serialization and ticket cookie format
are preserved, so upgrading does not invalidate existing sessions.

#### Error taxonomy

Every session error is classified into one of:

| Classification | Meaning | Default handling |
|---|---|---|
| unauthenticated | no session cookie was presented | normal sign-in redirect |
| not_found | ticket present but no session behind it (natural TTL expiry) | sign-in redirect, no alarm, no clear |
| unavailable | store timeout / connection failure / failover | degradation policy (below) |
| corrupt | stored data could not be decrypted or decoded | session destroyed + audit record |
| revoked | session deliberately invalidated with a reason | sign-in redirect, audit reason retained |

An `unavailable` read is **never** converted into a sign-out. The session is
left untouched and, once the store recovers, the same cookie works again.

#### Unavailable policy

`--session-unavailable-policy` selects what happens to a request whose session
read cannot be answered because the store is unavailable:

- `fail-closed` (default): the request is rejected with `503 Service
  Unavailable` and a `Retry-After` header. No authentication decision is made
  on uncertainty.
- `fail-open-stale`: the request proceeds using the last known good session
  snapshot cached in the process, with the request scope marked
  `SessionDegraded`. A degraded session is neither refreshed nor written back
  for the duration of the outage, and snapshots expire independently of the
  store (bounded by `--cookie-refresh`). If no snapshot exists, the request
  still fails closed with 503 — requests are never allowed without an identity.

#### Retries and reliable logout

Store operations are retried with exponential backoff (full jitter) up to
`--session-operation-max-retries`, each attempt bounded by
`--session-operation-timeout`. Only `unavailable` errors are retried;
not-found/corrupt/revoked are returned immediately.

Logout (`Clear`) has a separate, larger budget
(`--session-logout-max-retries`) and a strict ordering:

1. a shared revocation record is written first;
2. the session key is deleted from the store;
3. only then is the cookie removed.

If the store cannot be confirmed (e.g. during a primary/replica switchover),
logout returns an explicit error and **keeps the cookie**, so the user can
retry instead of believing they signed out while the session still exists.
The revocation record also acts as a second line of defence: even if the key
delete is delayed, a ticket matching a live revocation record is rejected on
every replica.

#### Revocation vs expiry

With `--session-revocation-enabled`, logout and administrative/provider-driven
invalidations write a revocation record (Redis key
`oauth2-proxy:revocation:<ticketID>`) with a TTL of
`--session-revocation-ttl` (default: the cookie expire duration). Because the
record lives in the shared store, revocation is effective on every replica.
Revocation reasons are recorded separately from natural TTL expiry:

`user-logout`, `admin-revoke`, `upstream-userinfo-changed`,
`refresh-token-revoked`, `corrupt-destroyed`.

Natural expiry writes no revocation record, so the audit trail keeps the two
events distinct.

#### Upstream user-info change propagation

By default a session keeps its embedded user information (groups, claims) until
it expires. `--session-userinfo-stale-max-age` bounds how stale that snapshot
may be: once it exceeds the age, the next request re-validates the identity
upstream. If the upstream rejects it (e.g. permissions were withdrawn), the
session is revoked with reason `upstream-userinfo-changed` instead of waiting
for expiry. If the upstream check itself cannot complete, the request degrades
as `unavailable` — a session is never revoked on uncertainty.

#### Reference of flags

| Flag | Default | Purpose |
|---|---|---|
| `--session-strict-semantics` | `false` | enable the strict wrapper |
| `--session-unavailable-policy` | `fail-closed` | `fail-closed` or `fail-open-stale` |
| `--session-operation-timeout` | `2s` | per-attempt store operation timeout |
| `--session-operation-max-retries` | `3` | retries for ordinary load/save operations |
| `--session-logout-max-retries` | `5` | retry budget for logout writes |
| `--session-revocation-enabled` | `false` | shared revocation records |
| `--session-revocation-ttl` | cookie expire | retention of revocation records |
| `--session-userinfo-stale-max-age` | `0` (disabled) | max age of embedded user info |

