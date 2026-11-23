# 不支持规则与原始日志字段覆盖缺口报告

## 1. 编译器显式拒绝的规则（`status = UNSUPPORTED`，共 13 / 45 条）

全部 13 条不支持规则均在能力检查阶段显式返回 `RuleStatus.UNSUPPORTED` 及具体原因，零静默忽略条件。

| # | 领域 | 规则文件 | Rule ID | 显式拒绝原因 (`unsupported_reasons`) |
| :---: | :--- | :--- | :--- | :--- |
| 10 | `windows_process_creation` | `proc_creation_win_hktl_sharpldapwhoami.yml` | `d9367cbb-c2e0-47ce-bdc0-128cb6da898d` | Unmapped Sigma field: 'Product' |
| 11 | `windows_process_creation` | `proc_creation_win_susp_cross_user_process_spawn.yml` | `d2b7a134-9c3e-4f8a-b56d-e0c1f8a29b47` | Unsupported Sigma modifier: SigmaFieldReferenceModifier |
| 16 | `powershell` | `proc_creation_win_powershell_base64_iex.yml` | `88f680b8-070e-402c-ae11-d2914f2257f1` | Unsupported Sigma modifier: SigmaBase64OffsetModifier |
| 19 | `powershell` | `posh_pc_download_via_webclient.yml` | `3236fcd0-b7e3-4433-b4f8-86ad61a9af2d` | Unmapped Sigma field: 'Data'; Unsupported Sigma logsource without OCSF class mapping (category='ps_classic_start', product='windows', service=None) |
| 25 | `file_activity` | `file_event_win_office_macro_files_from_susp_process.yml` | `b1c50487-1967-4315-a026-6491686d860e` | Unmapped Sigma field: 'ParentImage' |
| 26 | `file_activity` | `file_delete_win_delete_own_image.yml` | `f01d1f70-cd41-42ec-9c0b-26dd9c22bf29` | Unsupported Sigma modifier: SigmaFieldReferenceModifier |
| 31 | `network_connection` | `net_connection_win_certutil_initiated_connection.yml` | `0dba975d-a193-4ed1-a067-424df57570d1` | Unmapped Sigma field: 'Initiated' |
| 32 | `network_connection` | `net_connection_win_cmstp_initiated_connection.yml` | `efafe0bf-4238-479e-af8f-797bd3490d2d` | Unsupported Sigma modifier: SigmaCIDRModifier |
| 33 | `network_connection` | `net_firewall_cleartext_protocols.yml` | `d7fb8f0e-bd5f-45c2-b467-19571c490d7e` | Unmapped Sigma field: 'blocked' |
| 37 | `authentication` | `win_security_pass_the_hash_2.yml` | `8eef149c-bd26-49f2-9e5a-9b00e3af499b` | Unmapped Sigma field: 'SubjectUserSid'; Unmapped Sigma field: 'LogonProcessName'; Unmapped Sigma field: 'KeyLength' |
| 38 | `authentication` | `win_security_successful_external_remote_rdp_login.yml` | `259a9cdf-c4dd-4fa2-b243-2269e5ab18a2` | Unsupported Sigma modifier: SigmaCIDRModifier |
| 39 | `authentication` | `win_security_kerberos_asrep_roasting.yml` | `3e2f1b2c-4d5e-11ee-be56-0242ac120002` | Unmapped Sigma field: 'TicketEncryptionType'; Unmapped Sigma field: 'PreAuthType'; Unsupported Sigma logsource without OCSF class mapping (category=None, product='windows', service='security') |
| 45 | `dns` | `zeek_dns_torproxy.yml` | `a8322756-015c-42e7-afb1-436e85ed3ff5` | Unmapped Sigma field: 'query'; Unsupported Sigma logsource without OCSF class mapping (category=None, product='zeek', service='dns') |

## 2. 标准 OCSF `v1.4.0` 事件层可执行、但内置原始日志 YAML 映射尚未覆盖的规则（`DATA_COVERAGE = False`，共 11 / 32 条）

以下 11 条规则在标准 OCSF `v1.4.0` 输入上 `100%` 编译并正确执行，但当前内置 `configs/mappings/*.yaml` 尚未从原始日志提取对应字段或事件类，因此静态 `DATA_COVERAGE=False` 与端到端原始日志覆盖分开报告：

| # | 领域 | 规则文件 | 目标 `class_uid` | 缺失的内置原始日志映射字段 (`uncovered_fields`) |
| :---: | :--- | :--- | :---: | :--- |
| 01 | `windows_process_creation` | `proc_creation_win_bitsadmin_download.yml` | `[1007]` | `process.file.internal_name` |
| 02 | `windows_process_creation` | `proc_creation_win_certutil_download.yml` | `[1007]` | `process.file.internal_name` |
| 06 | `windows_process_creation` | `proc_creation_win_whoami_parent_anomaly.yml` | `[1007]` | `process.file.internal_name` |
| 09 | `windows_process_creation` | `proc_creation_win_renamed_whoami.yml` | `[1007]` | `process.file.internal_name` |
| 12 | `windows_process_creation` | `proc_creation_win_csc_susp_parent.yml` | `[1007]` | `process.file.internal_name` |
| 17 | `powershell` | `posh_ps_potential_invoke_mimikatz.yml` | `[1009]` | `class_uid:1009, script.script_content.value` |
| 18 | `powershell` | `posh_pm_invoke_obfuscation_clip.yml` | `[1009]` | `class_uid:1009, script.script_content.value` |
| 29 | `network_connection` | `net_connection_win_domain_ngrok_tunnel.yml` | `[4001]` | `dst_endpoint.hostname` |
| 30 | `network_connection` | `net_connection_win_domain_telegram_api_non_browser_access.yml` | `[4001]` | `dst_endpoint.hostname` |
| 36 | `authentication` | `win_security_susp_rottenpotato.yml` | `[3002]` | `src_endpoint.hostname` |
| 44 | `dns` | `net_dns_susp_txt_exec_strings.yml` | `[4003]` | `query.type` |
