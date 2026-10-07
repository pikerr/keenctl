# Agent Guidelines for keenctl

## Privacy & Security Guardrails (MANDATORY)

1. **Zero Real Network Data in Code**:
   - NEVER copy-paste real router query outputs (hardware MAC addresses, private local IP subnets, personal IoT/camera/miner device names, or personal cloud domains) into code, unit test fixtures, documentation, or commits.
   - ALWAYS use synthetic, standard documentation fixtures:
     - IP addresses: RFC 1918 (`192.168.1.x`, `192.168.2.x`) and RFC 5737 (`198.51.100.x`).
     - MAC addresses: Synthetic sequences (`aa:bb:cc:11:22:33`, `00:11:22:33:44:55`).
     - Device names: Generic labels (`Workstation`, `Laptop`, `Office Printer`, `Smart Plug`).
     - KeenDNS domains: Dummy placeholders (`your-router.keenetic.pro`, `test.keenetic.pro`).

2. **Stray Files Exclusion**:
   - Never write temporary scratch scripts or browser artifacts to the repository root.
   - Python scratch scripts belong in `.agent-tmp/`.
