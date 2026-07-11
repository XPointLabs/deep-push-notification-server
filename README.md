# Deep Push Notification Server

Production push gateway for Deep clients on XPoint Network. It accepts Session-compatible signed subscriptions, receives authenticated message events from XPoint storage nodes, encrypts notification metadata with XChaCha20-Poly1305, and delivers data-only notifications through Firebase Cloud Messaging.

The service never sends message plaintext or account metadata to Firebase. Provider payloads contain only `enc_payload` and protocol version `spns=1`.

## Local development

Requirements: .NET 10 SDK and PostgreSQL 16+.

```bash
dotnet test
dotnet run --project src/Deep.Push.Server
```

Configuration is supplied through ASP.NET Core environment variables:

- `Database__Host`, `Database__Port`, `Database__Name`, `Database__Username`
- `Database__PasswordFile` (preferred) or `Database__Password`
- `Push__FirebaseCredentialsPath`
- `Push__InternalTokenFile` for the co-located storage service
- `Push__RegistryUrl` for verification of signed external node notifications

Never commit a Firebase service-account file or database/internal token.

## Subscription signature v2

`/subscribe` and `/unsubscribe` require `sig_v: 2`. The Ed25519 signature covers a
versioned, UTF-8 canonical payload whose fields are emitted in this order as
`name=<utf8-byte-length>:<value>\n`:

```text
deep.push/subscribe/v2
pubkey
sig_ts
service
device_token
enc_key
want_data
namespaces
app_id
app_version
```

`/unsubscribe` uses the same framing with `pubkey`, `sig_ts`, `service`, and
`device_token`. Namespaces are ascending and unique; the server rejects
non-canonical casing, field values, missing `sig_v`, and legacy v1 signatures.

Deploy v2 clients before enabling a v2-only server fleet, then roll the server
atomically. The client refuses non-loopback HTTP push endpoints and persists a
local `RemoteSubscribed` state only after the server confirms the subscribe.
Loopback HTTP is limited to explicit local integration tests. Windows WNS is
polling-only until an actual WNS provider is configured server-side.

## Node authentication

External storage nodes sign the exact request body. The server accepts these headers:

- `X-XPoint-Node-Id`
- `X-XPoint-Notify-Timestamp`
- `X-XPoint-Notify-Signature`

The Ed25519 signature covers:

```text
XPOINT_PUSH_NOTIFY_V1\n{node-id}\n{unix-timestamp}\n{lowercase-sha256-of-body}
```

The public key must belong to an active node returned by the configured XPoint registry.
