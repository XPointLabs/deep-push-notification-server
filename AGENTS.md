# Deep Push Notification Server agent rules

The workspace rules in `../AGENTS.md` apply. This file contains only push-server deltas.

## Owns

- Authenticated push subscription and unsubscription lifecycle.
- Encrypted FCM and WNS provider delivery, retry and bounded diagnostics.
- Push subscription persistence, health/readiness and delivery counters.

Client notification UX belongs in the client repos; Docker/provider wiring and release evidence
belong in `deep-devops`; signed wire contracts belong in `deep-protocol`.

## Repository rules

- Require the current canonical subscription signature framing; reject unknown versions, stale
  timestamps, replay and invalid service/device bindings before persistence or provider calls.
- Push payloads remain opaque and minimal. Do not add plaintext message, sender, conversation or
  attachment metadata.
- Provider retry is bounded and idempotent; readiness must distinguish configuration, database and
  provider failures.
- Firebase service accounts, WNS secrets, database credentials and internal tokens are runtime
  inputs only and never enter logs, exceptions, snapshots, tests or committed config.
- Use standard TLS validation for provider endpoints; never add permissive callbacks.
- Update README and DevOps preflight/evidence when providers, config or endpoint behavior changes.

## Verify

```powershell
dotnet test Deep.Push.NotificationServer.slnx
```

Add API tests for auth/status behavior and provider tests for success, transient retry, terminal
failure and redacted diagnostics.
