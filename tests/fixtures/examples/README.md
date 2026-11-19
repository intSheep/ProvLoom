# Built-in Example Telemetry Suite

Minimal, deterministic security log samples aligned with OCSF v1.3 and PRD Acceptance Criteria (`AC-01`..`AC-10`):

- `assets_sample.json`: Authoritative host inventory (`win01.corp.local` `10.10.1.25`, `win02.corp.local` `10.10.1.26`).
- `auth_sample.jsonl`: Domain logon (`CORP\alice` -> `win01.corp.local`).
- `sysmon_sample.jsonl`:
  - `9001..9003`: `cmd.exe` spawns `powershell.exe` (`PID 4120`) on `win01`, writes `C:\Temp\stage.ps1`, and connects `10.10.1.25:51320 -> 198.51.100.42:443`.
  - `9101`: Separate `powershell.exe` (`PID 4120`) on `win02` to verify cross-host non-merging (`AC-09`).
- `zeek_dns_sample.jsonl`: `10.10.1.25` resolves `cdn-update.example.net` -> `198.51.100.42`.
- `zeek_conn_sample.jsonl` & `firewall_sample.csv`:
  - `fw-7001` / `C9xConn01`: Exact 5-tuple match (`10.10.1.25:51320 -> 198.51.100.42:443`) for deterministic cross-source correlation (`AC-06`).
  - `fw-7002`: Unverified external SNAT flow (`203.0.113.10:60111 -> 198.51.100.42:443`) that must NOT force-merge into `win01`'s process (`AC-09`).
