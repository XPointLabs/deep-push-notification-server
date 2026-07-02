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
