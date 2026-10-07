# Keenetic RCI Reference

Router Control Interface (RCI) is a JSON mirror of the router's internal command-line tree, not a REST API.

---

## Command Mapping

| Command | RCI Operation | Purpose |
|---|---|---|
| `keen get show/<path>` | `GET /rci/show/...` | Operational state (equivalent to `show ...`) |
| `keen get <config-path>` | `GET /rci/...` | Running configuration branch as JSON |
| `keen post <config-path> '<json>'` | `POST /rci/...` | Direct JSON mutation of a configuration branch |
| `keen cmd "<cli string>"` | `POST /rci/ {"parse": "..."}` | Executes native Keenetic CLI syntax via internal parser |

---

## Syntax Discovery (Avoid Guessing)

The router stores configuration as valid CLI. Inspect the running configuration to discover exact parameters:

1. Search existing configuration:
   ```bash
   keen cmd "show running-config" | grep -C 5 "<keyword>"
   ```
2. Convert CLI line to JSON or CLI call:
   - CLI Line: `host aa:bb:cc:dd:ee:ff policy Policy0`
   - Via JSON (`keen post`): `{"ip": {"hotspot": {"host": {"mac": "aa:bb:cc:dd:ee:ff", "policy": "Policy0"}}}}`
   - Via CLI (`keen cmd`): `keen cmd "ip hotspot host aa:bb:cc:dd:ee:ff policy Policy0"`

---

## Negation Pattern (`no`)

In KeeneticOS, deletion uses `"no": true` adjacent to the entity's arguments:

### JSON Deletion (`keen post`):
```bash
# Delete a routing policy
keen post ip/policy '{"no": true, "name": "Policy1"}'

# Delete an interface
keen post interface '{"no": true, "name": "Wireguard1"}'

# Delete a static DNS server
keen post ip/name-server '{"no": true, "address": "1.1.1.1", "interface": "Wireguard1"}'
```

### CLI Deletion (`keen cmd`):
```bash
keen cmd "no ip policy Policy1"
keen cmd "no interface Wireguard1"
```

A successful deletion returns a `status` block naming the removed entity. If no status block is returned, verify that the target existed.

---

## Essential Traps & Mitigation

1. **Silent 200 OK False Success**:
   - Sending an invalid field or wrong JSON path returns HTTP 200 `{}` and quietly ignores the change.
   - **Mitigation**: Always perform a read-back check (`keen get <path>`).
2. **Context Bloat on Large Trees**:
   - `keen get show/interface` returns ~32 KB covering all switch ports and tunnels.
   - **Mitigation**: Query specific sub-branches: `keen get show/interface/Bridge0`.
3. **Cascading Reference Cleanup**:
   - Deleting an interface or policy automatically removes dependent references (e.g. `permit global` rules in policies).
