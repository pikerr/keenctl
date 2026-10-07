# Safe Changes Protocol (Low Degrees of Freedom)

Modifying router settings remotely carries the risk of severing network access or locking oneself out. Execute configuration changes strictly according to this protocol.

---

## Safety Constraints

1. **Running-Config Only (RAM)**:
   - All mutations via `keen post` and `keen cmd` apply only to the running configuration in RAM.
   - If a change breaks connectivity or causes instability, a router reboot automatically reverts to the last saved configuration.
   - **Never run `keen save`** automatically. Only execute `keen save` after the human explicitly verifies the changes and requests saving.

2. **Router Fail-Safe Timer**:
   - Keenetic arms a ~3-minute fallback timer when configuration changes occur.
   - If the management session loses connectivity entirely, the router automatically reverts to startup-config.
   - **Warning**: This timer does *not* protect against incorrect logic (e.g. blocking the wrong MAC, breaking a VLAN, or breaking DNS). If the router remains reachable, no automatic revert occurs.

---

## Execution Checklist

For any configuration mutation, follow this strict 5-step sequence:

- [ ] **Step 1: Create Backup**
  ```bash
  keen backup
  ```
  Saves a timestamped copy of running-config into `~/.local/state/keenctl/backups/`.

- [ ] **Step 2: Inspect Target State**
  ```bash
  keen get <target-path>
  ```
  Record current values before modifying them.

- [ ] **Step 3: Apply Mutation**
  ```bash
  keen post <target-path> '<json>'
  # or
  keen cmd "<cli-command>"
  ```

- [ ] **Step 4: Self-Correction & Read-Back Verification**
  ```bash
  keen get <target-path>
  ```
  Verify that the target setting matches the intended value.
  *Failure loop*: If the response is unchanged or empty `{}` (silent rejection), re-verify syntax using `references/rci.md` and re-apply.

- [ ] **Step 5: Report to User**
  Inform the user of the exact changes applied in RAM. Ask whether they want to persist changes to flash via `keen save`.
