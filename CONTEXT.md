# Domain Model: keenctl

A lightweight, machine-friendly control plane (CLI and Python client) for Keenetic routers powered by KeeneticOS RCI.

## Glossary

### RCI (Router Control Interface)
The native JSON HTTP API of KeeneticOS (`/rci/`). Mirrors the internal router command-line hierarchy rather than a REST resource model.
- **GET** requests read operational state (`/rci/show/...`) or configuration branches.
- **POST** requests execute configuration mutations or batched CLI commands via the `{"parse": "..."}` endpoint.

### Challenge-Response Auth
Keenetic's native LAN authentication scheme over `/auth`:
1. Client requests `/auth` and receives HTTP 401 with `X-NDM-Realm` and `X-NDM-Challenge`.
2. Client computes `md5 = MD5(user:realm:password)` and `key = SHA256(challenge + md5)`.
3. Client posts credentials; router issues a session cookie with a randomized name.

### Session Sliding Window
The router session lifetime is 300 seconds (5 minutes), refreshed on each incoming request. If idle longer than 5 minutes, the router returns 401. The client must re-authenticate transparently.

### Running-Config vs Startup-Config
- **Running-Config**: Active configuration in router RAM. Discarded upon reboot.
- **Startup-Config**: Persistent configuration in flash storage.
- **Safe-by-default rule**: `keenctl` modifies *only* `running-config`. Mutations are discarded on reboot unless an explicit `save` command is called by the operator.

### Silent False Success
A quirk of Keenetic RCI where sending unknown fields or syntax errors returns HTTP 200 with an empty JSON object `{}` without applying changes. Mutations require read-back verification or status inspection.

### TTY-Aware Output
- When connected to a terminal (`sys.stdout.isatty() == True`): human-friendly formatted JSON or summary.
- When piped or redirected (`sys.stdout.isatty() == False`): raw, clean, machine-parsable JSON suitable for `jq` and AI agents.
