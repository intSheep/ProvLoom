# 阶段四至五：检测正确性、统计口径对账与公开数据集报告

## 1. 上一版指标偏差溯源与本轮统计口径修正

1. **上一版基线 F1 数字不一致原因：**
   - 上一轮 `correctness-report.md` 表内基线计数为语义集 `TP/FP/FN=22/2/5`（按公式 `2*22/(44+2+5) = 0.8627`）与 SigmaHQ 集 `61/1/5`（按公式 `2*61/(122+1+5) = 0.9531`），而口头回复摘要误写为手工计算错值 `0.8519 / 0.9524`。
   - 同时，上一轮评估脚本将编译/SQL 异常（`D05`, `D14`, `#08`, `#12`）返回的空命中列表当作 `actual=False`，错误地把异常规则下的负例计入 `TN`、正例计入 `FN`，并将 `#25` 的 3 条拒绝审计用例混入总用例数。
   - **本轮根治措施：** 统一采用四态结果（`MATCH` / `NO_MATCH` / `ERROR` / `UNSUPPORTED`），`ERROR` 单列且绝不计入 `TN`，`#25` 拒绝审计、`robustness_oracle` 与 `legacy_compat_oracle` 分表独立统计，所有 Markdown 表格均由 `run_evaluation.py` 从唯一 `evaluation-results.json` 自动生成。
2. **框架异常吞没修复：**
   - `src/provloom/detection/service.py` (`test_detection_rule`)：捕获 SQL 执行异常时，现显式返回 `RuleStatus.ERROR` 与 `execution_success=False`（此前返回原 `ENABLED` 状态且 `execution_success=None`）。
   - `src/provloom/storage/postgres/uow.py` (`_sqlite_regexp`)：移除 `except re.error: return 0`，禁止将非法正则静默转为 `False`。

## 2. Oracle 修订审计记录（含 BUG-03 `|base64` vs `|cased` 重审）

| 变更 ID | 涉及用例 / 规则 | 旧预期 | 新预期 | 修改原因 | 规范依据 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `ORACLE-CHG-01` | `D13_case_sensitivity:sem-13-tn-2-lowercase-false-base64 -> sem-13-tp-4-base64-lowercase-default-case-insensitive` | `False` | `True` | Round 1 erroneously assumed Sigma |base64 implies case-sensitive matching because the Base64 alphabet is case-sensitive. Per official Sigma Modifiers Specification v2.1.0 and pySigma v1.5.1 (SigmaBase64Modifier.modify -> SigmaString), |base64 only Base64-encodes the literal into an uncased SigmaString, which follows Sigma's default case-insensitive matching; only explicit |cased produces SigmaCasedString. | https://sigmahq.io/sigma-specification/specification/sigma-appendix-modifiers.html, https://github.com/SigmaHQ/pySigma/blob/v1.5.1/sigma/modifiers.py |
| `ORACLE-CHG-02` | `D15_array_fields & SigmaHQ #44 (net_dns_susp_txt_exec_strings.yml)` | `Tested DNS answers as string[] or scalar string` | `Standard suite uses OCSF v1.4.0 dns_answer[] objects ({'rdata': ...}) with negative sibling-attribute isolation cases; string[] / scalar cases moved to legacy_compat_oracle.json` | In OCSF v1.3.0 and v1.4.0 (dictionary.json & objects/dns_answer.json), DNS answers is dns_answer[] with required string attribute rdata. | https://github.com/ocsf/ocsf-schema/blob/1.4.0/dictionary.json, https://github.com/ocsf/ocsf-schema/blob/1.4.0/objects/dns_answer.json |
| `ORACLE-CHG-03` | `SigmaHQ #17 & #18 (Script Activity 1009)` | `Tested script.script_content as a flat string under OCSF 1.3.0 label` | `Upgraded target contract to OCSF v1.4.0 (6109cc5e834c1adfee67dda6c9bcfa5e37f79012) where Script Activity (1009) is standard and script.script_content is a long_string object whose text resides at script.script_content.value; added negative sibling-attribute cases and malformed scalar robustness case` | Script Activity (1009) was introduced in OCSF v1.4.0, and objects/long_string.json defines value as the required string attribute. | https://github.com/ocsf/ocsf-schema/blob/1.4.0/events/system/script_activity.json, https://github.com/ocsf/ocsf-schema/blob/1.4.0/objects/script.json, https://github.com/ocsf/ocsf-schema/blob/1.4.0/objects/long_string.json |
| `ORACLE-CHG-04` | `D06_numeric:sem-06-tn-3-malformed-nonnumeric & SigmaHQ #25 semantic_audit_only` | `Included in semantic_oracle.json and sigmahq_ground_truth.json respectively` | `Moved malformed non-numeric port case to robustness_oracle.json and #25's 3 rejection-audit cases to unsupported_audit_oracle.json` | Separate standard OCSF v1.4.0 execution test cases from deliberately invalid robustness inputs and unsupported-rule rejection audits. | https://github.com/ocsf/ocsf-schema/blob/1.4.0/dictionary.json |

## 3. 人工构造标准 OCSF `v1.4.0` 语义套件逐维结果（15 维，59 用例）

| 维度 | 规则文件 | 状态变化 | 基线 TP/FP/FN/TN | 修正后 TP/FP/FN/TN | Precision | Recall | F1 | FPR |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `D01_exact_match` | `sem_01_exact_match.yml` | `EXECUTABLE` → `EXECUTABLE` | 2/0/0/2 (ERR=0) | **2/0/0/2** (ERR=0) | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| `D02_contains` | `sem_02_contains.yml` | `EXECUTABLE` → `EXECUTABLE` | 1/0/0/2 (ERR=0) | **1/0/0/2** (ERR=0) | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| `D03_startswith` | `sem_03_startswith.yml` | `EXECUTABLE` → `EXECUTABLE` | 1/0/0/2 (ERR=0) | **1/0/0/2** (ERR=0) | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| `D04_endswith` | `sem_04_endswith.yml` | `EXECUTABLE` → `EXECUTABLE` | 1/0/0/2 (ERR=0) | **1/0/0/2** (ERR=0) | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| `D05_regex` | `sem_05_regex.yml` | `ERROR` → `EXECUTABLE` | 0/0/0/0 (ERR=4) | **2/0/0/2** (ERR=0) | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| `D06_numeric` | `sem_06_numeric.yml` | `EXECUTABLE` → `EXECUTABLE` | 2/0/0/2 (ERR=0) | **2/0/0/2** (ERR=0) | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| `D07_boolean_and` | `sem_07_and.yml` | `EXECUTABLE` → `EXECUTABLE` | 1/0/0/1 (ERR=0) | **1/0/0/1** (ERR=0) | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| `D08_boolean_or` | `sem_08_or.yml` | `EXECUTABLE` → `EXECUTABLE` | 2/0/0/1 (ERR=0) | **2/0/0/1** (ERR=0) | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| `D09_boolean_not` | `sem_09_not.yml` | `EXECUTABLE` → `EXECUTABLE` | 3/0/0/1 (ERR=0) | **3/0/0/1** (ERR=0) | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| `D10_selection_filter` | `sem_10_selection_filter.yml` | `EXECUTABLE` → `EXECUTABLE` | 1/0/0/3 (ERR=0) | **1/0/0/3** (ERR=0) | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| `D11_missing_field_exists` | `sem_11_missing_field.yml` | `EXECUTABLE` → `EXECUTABLE` | 2/0/0/2 (ERR=0) | **2/0/0/2** (ERR=0) | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| `D12_null_vs_empty` | `sem_12_null_value.yml` | `EXECUTABLE` → `EXECUTABLE` | 2/0/0/2 (ERR=0) | **2/0/0/2** (ERR=0) | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| `D13_case_sensitivity` | `sem_13_case_sensitivity.yml` | `EXECUTABLE` → `EXECUTABLE` | 5/0/0/2 (ERR=0) | **5/0/0/2** (ERR=0) | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| `D14_unicode_special_windash_sqli` | `sem_14_unicode_special_sqli.yml` | `UNSUPPORTED` → `EXECUTABLE` | 0/0/0/0 (ERR=0) | **3/0/0/1** (ERR=0) | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| `D15_array_fields` | `sem_15_array_fields.yml` | `EXECUTABLE` → `EXECUTABLE` | 1/1/1/3 (ERR=0) | **2/0/0/4** (ERR=0) | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| **合计** | **15 条语义规则** | — | **24/1/1/25 (ERR=4)** | **30/0/0/29 (ERR=0)** | **1.0000** | **1.0000** | **1.0000** | **0.0000** |

## 4. 32 条可执行 SigmaHQ 社区规则逐规则正确性结果（133 标准 OCSF `v1.4.0` 用例）

| # | 类别 | 规则文件 | OCSF Class | Raw 映射覆盖 | 基线 TP/FP/FN/TN/ERR | 修正后 TP/FP/FN/TN/ERR | Precision | Recall | F1 | FPR |
| :---: | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 01 | `windows_process_creation` | `proc_creation_win_bitsadmin_download.yml` | `[1007]` | Schema-Only | 2/0/0/2/E0 | **2/0/0/2/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 02 | `windows_process_creation` | `proc_creation_win_certutil_download.yml` | `[1007]` | Schema-Only | 2/0/0/2/E0 | **2/0/0/2/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 03 | `windows_process_creation` | `proc_creation_win_schtasks_creation_temp_folder.yml` | `[1007]` | Yes | 2/0/0/2/E0 | **2/0/0/2/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 04 | `windows_process_creation` | `proc_creation_win_wmiprvse_susp_child_processes.yml` | `[1007]` | Yes | 2/0/0/2/E0 | **2/0/0/2/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 05 | `windows_process_creation` | `proc_creation_win_svchost_uncommon_parent_process.yml` | `[1007]` | Yes | 2/0/0/2/E0 | **2/0/0/2/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 06 | `windows_process_creation` | `proc_creation_win_whoami_parent_anomaly.yml` | `[1007]` | Schema-Only | 2/0/0/2/E0 | **2/0/0/2/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 07 | `windows_process_creation` | `proc_creation_win_ping_hex_ip.yml` | `[1007]` | Yes | 2/0/0/2/E0 | **2/0/0/2/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 08 | `windows_process_creation` | `proc_creation_win_sysinternals_procdump_lsass.yml` | `[1007]` | Yes | 0/0/0/0/E0 | **2/0/0/2/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 09 | `windows_process_creation` | `proc_creation_win_renamed_whoami.yml` | `[1007]` | Schema-Only | 2/0/0/2/E0 | **2/0/0/2/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 12 | `windows_process_creation` | `proc_creation_win_csc_susp_parent.yml` | `[1007]` | Schema-Only | 0/0/0/0/E4 | **2/0/0/2/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 13 | `powershell` | `proc_creation_win_hktl_empire_powershell_launch.yml` | `[1007]` | Yes | 2/0/0/2/E0 | **2/0/0/2/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 14 | `powershell` | `proc_creation_win_powershell_download_iex.yml` | `[1007]` | Yes | 2/0/0/2/E0 | **2/0/0/2/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 15 | `powershell` | `proc_creation_win_powershell_token_obfuscation.yml` | `[1007]` | Yes | 2/0/0/2/E0 | **2/0/0/2/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 17 | `powershell` | `posh_ps_potential_invoke_mimikatz.yml` | `[1009]` | Schema-Only | 2/0/0/3/E0 | **2/0/0/3/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 18 | `powershell` | `posh_pm_invoke_obfuscation_clip.yml` | `[1009]` | Schema-Only | 0/0/2/3/E0 | **2/0/0/3/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 20 | `file_activity` | `file_event_win_lsass_default_dump_file_names.yml` | `[1001]` | Yes | 2/0/0/2/E0 | **2/0/0/2/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 21 | `file_activity` | `file_event_win_taskmgr_lsass_dump.yml` | `[1001]` | Yes | 2/0/0/2/E0 | **2/0/0/2/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 22 | `file_activity` | `file_event_win_powershell_drop_binary_or_script.yml` | `[1001]` | Yes | 2/0/0/2/E0 | **2/0/0/2/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 23 | `file_activity` | `file_delete_win_delete_backup_file.yml` | `[1001]` | Yes | 2/0/0/2/E0 | **2/0/0/2/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 24 | `file_activity` | `file_change_win_unusual_modification_by_dns_exe.yml` | `[1001]` | Yes | 2/0/0/2/E0 | **2/0/0/2/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 27 | `network_connection` | `net_connection_win_eqnedt.yml` | `[4001]` | Yes | 2/0/0/2/E0 | **2/0/0/2/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 28 | `network_connection` | `net_connection_win_notepad.yml` | `[4001]` | Yes | 2/0/0/2/E0 | **2/0/0/2/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 29 | `network_connection` | `net_connection_win_domain_ngrok_tunnel.yml` | `[4001]` | Schema-Only | 2/0/0/2/E0 | **2/0/0/2/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 30 | `network_connection` | `net_connection_win_domain_telegram_api_non_browser_access.yml` | `[4001]` | Schema-Only | 2/0/0/2/E0 | **2/0/0/2/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 34 | `authentication` | `win_security_rdp_localhost_login.yml` | `[3002]` | Yes | 2/0/0/2/E0 | **2/0/0/2/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 35 | `authentication` | `win_security_susp_logon_newcredentials.yml` | `[3002]` | Yes | 2/0/0/2/E0 | **2/0/0/2/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 36 | `authentication` | `win_security_susp_rottenpotato.yml` | `[3002]` | Schema-Only | 2/0/0/2/E0 | **2/0/0/2/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 40 | `dns` | `dns_query_win_cloudflared_communication.yml` | `[4003]` | Yes | 2/0/0/2/E0 | **2/0/0/2/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 41 | `dns` | `dns_query_win_dns_server_discovery_via_ldap_query.yml` | `[4003]` | Yes | 2/0/0/2/E0 | **2/0/0/2/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 42 | `dns` | `dns_query_win_regsvr32_dns_query.yml` | `[4003]` | Yes | 2/0/0/2/E0 | **2/0/0/2/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 43 | `dns` | `net_dns_mal_cobaltstrike.yml` | `[4003]` | Yes | 2/0/0/2/E0 | **2/0/0/2/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| 44 | `dns` | `net_dns_susp_txt_exec_strings.yml` | `[4003]` | Schema-Only | 2/1/0/4/E0 | **2/0/0/5/E0** | 1.0000 | 1.0000 | **1.0000** | 0.0000 |
| **合计** | **32 条规则** | — | — | **21 Raw / 11 Schema-Only** | **58/1/2/64/E4** | **64/0/0/69/E0** | **1.0000** | **1.0000** | **1.0000** | **0.0000** |

## 5. 公开数据集端到端测试与全量记录守恒对账

每份数据集均通过严格守恒断言：
1. `ingest_total == accepted + duplicate + ingest_failed`
2. `accepted == mapped + passthrough + parse_or_normalize_failed`

（注：上一轮 `otrf_lsass_comsvcs_t1003_001` 的 `51` 行输入中含 **1 条完全重复原始记录** `duplicate_count=1`，故 `accepted=50 = 6 mapped + 20 passthrough + 24 parse_failed`，现已完整列示对账；所有无标签背景事件均标记为 `UNKNOWN`，不计入 `TN`。此外，公开原始数据集上的 `OCSF 结构/枚举错误 = 0`，而 Sysmon EID 22 原生不含端点且 OTRF 使用 `Hostname` 而非 `Computer`，源日志缺失导致的 `at_least_one` 约束缺口单独列示、**绝不在归一化层伪造字段**。）

| 数据集 ID | 源类型 | 输入总行数 | 接收 (`accepted`) | **去重 (`duplicate`)** | 接入失败 (`ingest_fail`) | OCSF 映射 (`MAPPED`) | 兜底透传 (`class_uid=0`) | 解析/归一化失败 | OCSF 结构/枚举错误 | 源日志约束缺口 (`at_least_one`) | 总命中 `RuleMatch` | `UNKNOWN` 背景事件 | 已知攻击检出核验 |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `otrf_bitsadmin_t1197` | `sysmon` | 66 | 66 | **0** | 0 | 21 | 15 | 30 | 0 | 13 | 1 | 20 | `proc_creation_win_bitsadmin_download.yml`=1 (PASS) |
| `otrf_lsass_comsvcs_t1003_001` | `sysmon` | 51 | 50 | **1** | 0 | 6 | 20 | 24 | 0 | 6 | 1 | 5 | `file_event_win_lsass_default_dump_file_names.yml`=1 (PASS) |
| `splunk_atomic_t1053_005_sysmon` | `sysmon` | 552 | 552 | **0** | 0 | 542 | 10 | 0 | 0 | 542 | 500 | 493 | `file_event_win_powershell_drop_binary_or_script.yml`=49 (PASS) |
| `splunk_t1021_001_zeek_conn` | `zeek_conn` | 1 | 1 | **0** | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | 无预期攻击标签（纯背景流量） |
| `splunk_t1021_001_sysmon_xml_format_audit` | `sysmon (XML)` | 5 | 5 | 0 | 0 | 0 | 0 | 5 | 0 | 0 | 0 | 0 | 非 JSONL 的原始 XML 行 100% 记入 `pipeline_failures`，零静默丢数 |

## 6. 32 条可执行 SigmaHQ 规则独立测试报告

### #01 `proc_creation_win_bitsadmin_download.yml` (`d059842b-6b9d-4ed1-b5c3-5b89143c6ede`)
- **标题 / 等级 / 版本:** File Download Via Bitsadmin · `medium` · `2023-02-15`
- **OCSF v1.4.0 映射:** `class_uid=[1007]` · `field_mappings={"CommandLine": "process.cmd_line", "Image": "process.file.path", "OriginalFileName": "process.file.internal_name"}` · `static_data_coverage=False`
- **指标:** `TP=2, FP=0, FN=0, TN=2, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-01-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): Image ends with \bitsadmin.exe and CommandLine contains ' /transfer '.
  - `gt-01-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): Renamed binary matched via OriginalFileName=bitsadmin.exe with ' /addfile ' and 'http'.
  - `gt-01-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): bitsadmin /list lacks transfer or create/addfile+http flags.
  - `gt-01-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): Has ' /create ' (selection_cli_1) but lacks 'http' (selection_cli_2).

### #02 `proc_creation_win_certutil_download.yml` (`19b08b1c-861d-4e75-a1ef-ea0c1baf202b`)
- **标题 / 等级 / 版本:** Suspicious Download Via Certutil.EXE · `medium` · `2025-12-01`
- **OCSF v1.4.0 映射:** `class_uid=[1007]` · `field_mappings={"CommandLine": "process.cmd_line", "Image": "process.file.path", "OriginalFileName": "process.file.internal_name"}` · `static_data_coverage=False`
- **指标:** `TP=2, FP=0, FN=0, TN=2, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-02-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): certutil.exe with 'urlcache ' and 'http'.
  - `gt-02-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): Matched OriginalFileName CertUtil.exe with 'verifyctl ' and 'http'.
  - `gt-02-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): Local hashfile operation without download flags or http.
  - `gt-02-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): Has 'urlcache ' but lacks 'http'.

### #03 `proc_creation_win_schtasks_creation_temp_folder.yml` (`39019a4e-317f-4ce3-ae63-309a8c6b53c5`)
- **标题 / 等级 / 版本:** Suspicious Scheduled Task Creation Involving Temp Folder · `high` · `2022-10-09`
- **OCSF v1.4.0 映射:** `class_uid=[1007]` · `field_mappings={"CommandLine": "process.cmd_line", "Image": "process.file.path"}` · `static_data_coverage=True`
- **指标:** `TP=2, FP=0, FN=0, TN=2, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-03-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): schtasks.exe with all three tokens: ' /create ', ' /sc once ', and '\Temp\'.
  - `gt-03-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): Case-insensitive match on uppercase SCHTASKS flags and \Temp\.
  - `gt-03-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): Uses '/sc daily' instead of required ' /sc once '.
  - `gt-03-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): Benign schtasks query.

### #04 `proc_creation_win_wmiprvse_susp_child_processes.yml` (`8a582fe2-0882-4b89-a82a-da6b2dc32937`)
- **标题 / 等级 / 版本:** Suspicious WmiPrvSE Child Process · `high` · `2023-11-10`
- **OCSF v1.4.0 映射:** `class_uid=[1007]` · `field_mappings={"CommandLine": "process.cmd_line", "Image": "process.file.path", "ParentImage": "process.parent_process.file.path"}` · `static_data_coverage=True`
- **指标:** `TP=2, FP=0, FN=0, TN=2, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-04-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): WmiPrvSE.exe directly spawning mshta.exe (selection_children_1).
  - `gt-04-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): WmiPrvSE.exe spawning cmd.exe invoking powershell (selection_children_2).
  - `gt-04-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): Excluded by filter_main_msiexec (msiexec.exe with '/i ').
  - `gt-04-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): cmd.exe under WmiPrvSE without scripting interpreter token in CommandLine.

### #05 `proc_creation_win_svchost_uncommon_parent_process.yml` (`01d2e2a1-5f09-44f7-9fc1-24faa7479b6d`)
- **标题 / 等级 / 版本:** Uncommon Svchost Parent Process · `medium` · `2026-10-19`
- **OCSF v1.4.0 映射:** `class_uid=[1007]` · `field_mappings={"CommandLine": "process.cmd_line", "Image": "process.file.path", "ParentImage": "process.parent_process.file.path"}` · `static_data_coverage=True`
- **指标:** `TP=2, FP=0, FN=0, TN=2, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-05-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): svchost.exe spawned by uncommon parent injector.exe.
  - `gt-05-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): svchost.exe spawned by svchost.exe with non-whitelisted CommandLine suffix.
  - `gt-05-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): Standard services.exe parent filtered by filter_main_generic.
  - `gt-05-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): Boundary: missing ParentImage filtered out by filter_main_parent_null.

### #06 `proc_creation_win_whoami_parent_anomaly.yml` (`8de1cbe8-d6f5-496d-8237-5f44a721c7a0`)
- **标题 / 等级 / 版本:** Whoami.EXE Execution Anomaly · `medium` · `2025-03-06`
- **OCSF v1.4.0 映射:** `class_uid=[1007]` · `field_mappings={"Image": "process.file.path", "OriginalFileName": "process.file.internal_name", "ParentImage": "process.parent_process.file.path"}` · `static_data_coverage=False`
- **指标:** `TP=2, FP=0, FN=0, TN=2, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-06-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): whoami.exe spawned by IIS worker w3wp.exe.
  - `gt-06-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): Renamed whoami.exe spawned by httpd.exe.
  - `gt-06-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): Interactive shell cmd.exe filtered by filter_main_known_parents.
  - `gt-06-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): Boundary: ParentImage '-' filtered by filter_main_parent_empty.

### #07 `proc_creation_win_ping_hex_ip.yml` (`1a0d4aba-7668-4365-9ce4-6d79ab088dfd`)
- **标题 / 等级 / 版本:** Ping Hex IP · `high` · `2025-10-17`
- **OCSF v1.4.0 映射:** `class_uid=[1007]` · `field_mappings={"CommandLine": "process.cmd_line", "Image": "process.file.path"}` · `static_data_coverage=True`
- **指标:** `TP=2, FP=0, FN=0, TN=2, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-07-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): ping.exe with 8-digit hex IP 0x7f000001 matches 0x[a-fA-F0-9]{8}.
  - `gt-07-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): Uppercase hex digits 0xC633640A match regex.
  - `gt-07-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): Standard dotted-quad IPv4 does not match hex regex.
  - `gt-07-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): Boundary: only 5 hex digits (< 8 required by {8}).

### #08 `proc_creation_win_sysinternals_procdump_lsass.yml` (`5afee48e-67dd-4e03-a783-f74259dcf998`)
- **标题 / 等级 / 版本:** Potential LSASS Process Dump Via Procdump · `high` · `2025-10-19`
- **OCSF v1.4.0 映射:** `class_uid=[1007]` · `field_mappings={"CommandLine": "process.cmd_line"}` · `static_data_coverage=True`
- **指标:** `TP=2, FP=0, FN=0, TN=2, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-08-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): Standard hyphen '-ma ' and ' ls' match procdump LSASS rule.
  - `gt-08-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): Windash slash variant ' /ma ' and ' ls' match procdump LSASS rule.
  - `gt-08-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): Dumping notepad.exe lacks ' ls' / ' keyiso' / ' samss'.
  - `gt-08-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): Has ' ls' but lacks '-ma '/' -mm '/' -mp '.

### #09 `proc_creation_win_renamed_whoami.yml` (`f1086bf7-a0c4-4a37-9102-01e573caf4a0`)
- **标题 / 等级 / 版本:** Renamed Whoami Execution · `critical` · `2022-10-09`
- **OCSF v1.4.0 映射:** `class_uid=[1007]` · `field_mappings={"Image": "process.file.path", "OriginalFileName": "process.file.internal_name"}` · `static_data_coverage=False`
- **指标:** `TP=2, FP=0, FN=0, TN=2, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-09-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): OriginalFileName is whoami.exe while Image is renamed.
  - `gt-09-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): Case-insensitive OriginalFileName match with .com rename.
  - `gt-09-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): Legitimate unrenamed \whoami.exe excluded by filter.
  - `gt-09-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): Unrelated executable.

### #12 `proc_creation_win_csc_susp_parent.yml` (`b730a276-6b63-41b8-bcf8-55930c8fc6ee`)
- **标题 / 等级 / 版本:** Csc.EXE Execution Form Potentially Suspicious Parent · `high` · `2026-03-23`
- **OCSF v1.4.0 映射:** `class_uid=[1007]` · `field_mappings={"Image": "process.file.path", "OriginalFileName": "process.file.internal_name", "ParentCommandLine": "process.parent_process.cmd_line", "ParentImage": "process.parent_process.file.path"}` · `static_data_coverage=False`
- **指标:** `TP=2, FP=0, FN=0, TN=2, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-12-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): csc.exe spawned by wscript.exe (selection_parent_generic) outside Program Files.
  - `gt-12-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): csc.exe parent in \AppData\Roaming\agent.exe matches regex selection_parent_susp_location.
  - `gt-12-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): Filtered by filter_main_programfiles (ParentImage starts with C:\Program Files\).
  - `gt-12-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): Filtered by filter_main_w3p.

### #13 `proc_creation_win_hktl_empire_powershell_launch.yml` (`79f4ede3-402e-41c8-bc3e-ebbf5f162581`)
- **标题 / 等级 / 版本:** HackTool - Empire PowerShell Launch Parameters · `high` · `2023-02-21`
- **OCSF v1.4.0 映射:** `class_uid=[1007]` · `field_mappings={"CommandLine": "process.cmd_line"}` · `static_data_coverage=True`
- **指标:** `TP=2, FP=0, FN=0, TN=2, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-13-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): Matches canonical Empire launcher flags.
  - `gt-13-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): Matches '-nop -exec bypass -EncodedCommand ' variant.
  - `gt-13-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): Benign admin script execution.
  - `gt-13-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): Missing CommandLine must not match.

### #14 `proc_creation_win_powershell_download_iex.yml` (`85b0b087-eddf-4a2b-b033-d771fa2b9775`)
- **标题 / 等级 / 版本:** PowerShell Download and Execution Cradles · `high` · `2025-07-18`
- **OCSF v1.4.0 映射:** `class_uid=[1007]` · `field_mappings={"CommandLine": "process.cmd_line"}` · `static_data_coverage=True`
- **指标:** `TP=2, FP=0, FN=0, TN=2, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-14-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): Contains both '.DownloadString(' and 'IEX('.
  - `gt-14-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): Contains 'iwr ' and '| IEX'.
  - `gt-14-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): Download without IEX execution.
  - `gt-14-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): IEX without download cradle.

### #15 `proc_creation_win_powershell_token_obfuscation.yml` (`deb9b646-a508-44ee-b7c9-d8965921c6b6`)
- **标题 / 等级 / 版本:** Powershell Token Obfuscation - Process Creation · `high` · `2026-03-16`
- **OCSF v1.4.0 映射:** `class_uid=[1007]` · `field_mappings={"CommandLine": "process.cmd_line"}` · `static_data_coverage=True`
- **指标:** `TP=2, FP=0, FN=0, TN=2, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-15-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): Backtick-obfuscated token matches \w+`(?:\w+|-|.)`[\w+|\s].
  - `gt-15-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): Matches obfuscated ${`e`n`v:PATH} regex without matching literal ${env:path} filter.
  - `gt-15-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): Unobfuscated ${env:path} excluded by filter_main_envpath.
  - `gt-15-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): Clean PowerShell command without obfuscation.

### #17 `posh_ps_potential_invoke_mimikatz.yml` (`189e3b02-82b2-4b90-9662-411eb64486d4`)
- **标题 / 等级 / 版本:** Potential Invoke-Mimikatz PowerShell Script · `high` · `2022-09-28`
- **OCSF v1.4.0 映射:** `class_uid=[1009]` · `field_mappings={"ScriptBlockText": "script.script_content.value"}` · `static_data_coverage=False`
- **指标:** `TP=2, FP=0, FN=0, TN=3, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-17-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): ScriptBlockText contains both 'DumpCreds' and 'DumpCerts' (selection_1).
  - `gt-17-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): ScriptBlockText contains 'sekurlsa::logonpasswords' (selection_2).
  - `gt-17-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): Only one of the two required tokens in selection_1 (DumpCerts absent).
  - `gt-17-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): Benign certificate inspection script.
  - `gt-17-tn-3-sibling-only` (expected=`False` → outcome=`NO_MATCH`, **TN**): OCSF v1.4.0 long_string isolation: suspicious text appears only in script.name/uid, while script.script_content.value is benign.

### #18 `posh_pm_invoke_obfuscation_clip.yml` (`a136cde0-61ad-4a61-9b82-8dc490e60dd2`)
- **标题 / 等级 / 版本:** Invoke-Obfuscation CLIP+ Launcher - PowerShell Module · `high` · `2024-04-05`
- **OCSF v1.4.0 映射:** `class_uid=[1009]` · `field_mappings={"Payload": "script.script_content.value"}` · `static_data_coverage=False`
- **指标:** `TP=2, FP=0, FN=0, TN=3, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-18-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): Matches Invoke-Obfuscation CLIP case-sensitive regex in Payload.
  - `gt-18-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): Matches cmd.exe /r ... clip && ... clipboard]::( \"{d}...-f..." variant.
  - `gt-18-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): Standard Get-Clipboard cmdlet.
  - `gt-18-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): Simple cmd pipe to clip.exe without clipboard reflection obfuscation.
  - `gt-18-tn-3-sibling-only` (expected=`False` → outcome=`NO_MATCH`, **TN**): OCSF v1.4.0 long_string isolation: suspicious text appears only in script.name/uid, while script.script_content.value is benign.

### #20 `file_event_win_lsass_default_dump_file_names.yml` (`a5a2d357-1ab8-4675-a967-ef9990a59391`)
- **标题 / 等级 / 版本:** LSASS Process Memory Dump Files · `high` · `2024-10-08`
- **OCSF v1.4.0 映射:** `class_uid=[1001]` · `field_mappings={"TargetFilename": "file.path"}` · `static_data_coverage=True`
- **指标:** `TP=2, FP=0, FN=0, TN=2, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-20-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): TargetFilename contains '\lsass' and '.dmp' (selection_3).
  - `gt-20-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): TargetFilename contains '\nanodump' and ends with '.dmp' (selection_5).
  - `gt-20-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): Crash dump unrelated to lsass/nanodump/SQLDmpr.
  - `gt-20-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): lsass.exe binary path is not a dump archive/file.

### #21 `file_event_win_taskmgr_lsass_dump.yml` (`69ca12af-119d-44ed-b50f-a47af0ebc364`)
- **标题 / 等级 / 版本:** LSASS Process Memory Dump Creation Via Taskmgr.EXE · `high` · `2023-10-19`
- **OCSF v1.4.0 映射:** `class_uid=[1001]` · `field_mappings={"Image": "actor.process.file.path", "TargetFilename": "file.path"}` · `static_data_coverage=True`
- **指标:** `TP=2, FP=0, FN=0, TN=2, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-21-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): taskmgr.exe writing lsass .DMP into AppData\Local\Temp\.
  - `gt-21-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): SysWOW64 Taskmgr.exe case-insensitive match.
  - `gt-21-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): taskmgr.exe dumping notepad rather than lsass.
  - `gt-21-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): Created by procdump.exe rather than taskmgr.exe.

### #22 `file_event_win_powershell_drop_binary_or_script.yml` (`7047d730-036f-4f40-b9d8-1c63e36d5e62`)
- **标题 / 等级 / 版本:** Potential Binary Or Script Dropper Via PowerShell · `medium` · `2025-07-04`
- **OCSF v1.4.0 映射:** `class_uid=[1001]` · `field_mappings={"Image": "actor.process.file.path", "TargetFilename": "file.path"}` · `static_data_coverage=True`
- **指标:** `TP=2, FP=0, FN=0, TN=2, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-22-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): powershell.exe dropping .exe in C:\Users\Public\ (not in Temp filter).
  - `gt-22-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): pwsh.exe dropping .vbs in Temp (filter_main_user_temp only excludes .dll and .exe, NOT .vbs!).
  - `gt-22-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): Excluded by filter_main_user_temp (.dll in C:\Users\...\AppData\Local\Temp\).
  - `gt-22-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): .txt extension is not in suspicious binary/script list.

### #23 `file_delete_win_delete_backup_file.yml` (`06125661-3814-4e03-bfa2-1e4411c60ac3`)
- **标题 / 等级 / 版本:** Backup Files Deleted · `medium` · `2023-02-15`
- **OCSF v1.4.0 映射:** `class_uid=[1001]` · `field_mappings={"Image": "actor.process.file.path", "TargetFilename": "file.path"}` · `static_data_coverage=True`
- **指标:** `TP=2, FP=0, FN=0, TN=2, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-23-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): cmd.exe deleting .wbcat backup file (activity_id=4).
  - `gt-23-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): powershell.exe deleting .VHD backup disk.
  - `gt-23-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): Boundary: file creation (activity_id=1) must not match file_delete (activity_id=4).
  - `gt-23-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): Non-shell backup agent executable.

### #24 `file_change_win_unusual_modification_by_dns_exe.yml` (`9f383dc0-fdeb-4d56-acbc-9f9f4f8f20f3`)
- **标题 / 等级 / 版本:** Unusual File Modification by dns.exe · `high` · `2022-09-27`
- **OCSF v1.4.0 映射:** `class_uid=[1001]` · `field_mappings={"Image": "actor.process.file.path", "TargetFilename": "file.path"}` · `static_data_coverage=True`
- **指标:** `TP=2, FP=0, FN=0, TN=2, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-24-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): dns.exe modifying evil.dll (not \dns.log).
  - `gt-24-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): dns.exe writing webshell.
  - `gt-24-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): Normal \dns.log modification excluded by filter.
  - `gt-24-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): Actor is svchost.exe, not dns.exe.

### #27 `net_connection_win_eqnedt.yml` (`a66bc059-c370-472c-a0d7-f8fd1bf9d583`)
- **标题 / 等级 / 版本:** Network Connection Initiated By Eqnedt32.EXE · `high` · `2024-05-31`
- **OCSF v1.4.0 映射:** `class_uid=[4001]` · `field_mappings={"Image": "actor.process.file.path"}` · `static_data_coverage=True`
- **指标:** `TP=2, FP=0, FN=0, TN=2, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-27-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): Equation Editor EQNEDT32.EXE initiating network activity (CVE-2017-11882).
  - `gt-27-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): eqnedt32.exe from Temp initiating outbound connection.
  - `gt-27-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): WINWORD.EXE is not eqnedt32.exe.
  - `gt-27-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): Firewall/Zeek flow without actor.process.file.path.

### #28 `net_connection_win_notepad.yml` (`e81528db-fc02-45e8-8e98-4e84aba1f10b`)
- **标题 / 等级 / 版本:** Network Connection Initiated Via Notepad.EXE · `high` · `2024-02-02`
- **OCSF v1.4.0 映射:** `class_uid=[4001]` · `field_mappings={"DestinationPort": "dst_endpoint.port", "Image": "actor.process.file.path"}` · `static_data_coverage=True`
- **指标:** `TP=2, FP=0, FN=0, TN=2, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-28-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): Hollowed notepad.exe connecting to port 443 (!= 9100).
  - `gt-28-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): Boundary: notepad.exe with missing DestinationPort is not port 9100, so must match.
  - `gt-28-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): JetDirect printing port 9100 excluded by filter_optional_printing.
  - `gt-28-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): notepad++.exe does not end with '\notepad.exe'.

### #29 `net_connection_win_domain_ngrok_tunnel.yml` (`1d08ac94-400d-4469-a82f-daee9a908849`)
- **标题 / 等级 / 版本:** Communication To Ngrok Tunneling Service Initiated · `high` · `2024-02-02`
- **OCSF v1.4.0 映射:** `class_uid=[4001]` · `field_mappings={"DestinationHostname": "dst_endpoint.hostname"}` · `static_data_coverage=False`
- **指标:** `TP=2, FP=0, FN=0, TN=2, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-29-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): DestinationHostname contains 'tunnel.us.ngrok.com'.
  - `gt-29-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): DestinationHostname contains 'tunnel.ap.ngrok.com'.
  - `gt-29-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): dashboard.ngrok.com is not a regional tunnel.*.ngrok.com endpoint.
  - `gt-29-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): IP-only network event without DestinationHostname.

### #30 `net_connection_win_domain_telegram_api_non_browser_access.yml` (`c3dbbc9f-ef1d-470a-a90a-d343448d5875`)
- **标题 / 等级 / 版本:** Suspicious Non-Browser Network Communication With Telegram API · `medium` · `2023-05-19`
- **OCSF v1.4.0 映射:** `class_uid=[4001]` · `field_mappings={"DestinationHostname": "dst_endpoint.hostname", "Image": "actor.process.file.path"}` · `static_data_coverage=False`
- **指标:** `TP=2, FP=0, FN=0, TN=2, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-30-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): powershell.exe accessing api.telegram.org (non-browser).
  - `gt-30-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): Custom binary accessing api.telegram.org.
  - `gt-30-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): Standard Chrome browser excluded by filter_main_chrome.
  - `gt-30-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): EdgeCore WebView2 excluded by filter_main_edge_2.

### #34 `win_security_rdp_localhost_login.yml` (`51e33403-2a37-4d66-a574-1fda1782cc31`)
- **标题 / 等级 / 版本:** RDP Login from Localhost · `high` · `2022-10-09`
- **OCSF v1.4.0 映射:** `class_uid=[3002]` · `field_mappings={"EventID": "unmapped.EventID", "IpAddress": "src_endpoint.ip", "LogonType": "logon_type_id"}` · `static_data_coverage=True`
- **指标:** `TP=2, FP=0, FN=0, TN=2, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-34-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): EventID 4624, LogonType 10 (RemoteInteractive), IpAddress 127.0.0.1 (tunneled RDP).
  - `gt-34-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): IPv6 loopback ::1 RDP logon.
  - `gt-34-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): Normal LAN IP 10.10.1.55 RDP logon.
  - `gt-34-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): LogonType 3 (Network) instead of 10 (RemoteInteractive).

### #35 `win_security_susp_logon_newcredentials.yml` (`def8b624-e08f-4ae1-8612-1ba21190da6b`)
- **标题 / 等级 / 版本:** Outgoing Logon with New Credentials · `low` · `2022-04-06`
- **OCSF v1.4.0 映射:** `class_uid=[3002]` · `field_mappings={"EventID": "unmapped.EventID", "LogonType": "logon_type_id"}` · `static_data_coverage=True`
- **指标:** `TP=2, FP=0, FN=0, TN=2, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-35-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): EventID 4624 with LogonType 9 (NewCredentials / runas /netonly).
  - `gt-35-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): Rubeus /createnetonly LogonType 9.
  - `gt-35-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): Interactive LogonType 2.
  - `gt-35-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): Failed logon EventID 4625 rather than 4624.

### #36 `win_security_susp_rottenpotato.yml` (`16f5d8ca-44bd-47c8-acbe-6fc95a16c12f`)
- **标题 / 等级 / 版本:** RottenPotato Like Attack Pattern · `high` · `2022-12-22`
- **OCSF v1.4.0 映射:** `class_uid=[3002]` · `field_mappings={"EventID": "unmapped.EventID", "IpAddress": "src_endpoint.ip", "LogonType": "logon_type_id", "TargetUserName": "user.name", "WorkstationName": "src_endpoint.hostname"}` · `static_data_coverage=False`
- **指标:** `TP=2, FP=0, FN=0, TN=2, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-36-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): RottenPotato local NTLM reflection signature (4624, Type 3, ANONYMOUS LOGON, '-', 127.0.0.1).
  - `gt-36-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): IPv6 loopback ::1 RottenPotato variant.
  - `gt-36-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): WorkstationName is 'WS01' rather than '-'.
  - `gt-36-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): Authenticated named user rather than ANONYMOUS LOGON.

### #40 `dns_query_win_cloudflared_communication.yml` (`a1d9eec5-33b2-4177-8d24-27fe754d0812`)
- **标题 / 等级 / 版本:** Cloudflared Tunnels Related DNS Requests · `medium` · `2023-12-20`
- **OCSF v1.4.0 映射:** `class_uid=[4003]` · `field_mappings={"QueryName": "query.hostname"}` · `static_data_coverage=True`
- **指标:** `TP=2, FP=0, FN=0, TN=2, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-40-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): Ends with '.v2.argotunnel.com'.
  - `gt-40-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): Ends with 'trycloudflare.com'.
  - `gt-40-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): Main cloudflare.com website is not an argotunnel/trycloudflare tunnel.
  - `gt-40-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): Does not end with cloudflared tunnel domain.

### #41 `dns_query_win_dns_server_discovery_via_ldap_query.yml` (`a21bcd7e-38ec-49ad-b69a-9ea17e69509e`)
- **标题 / 等级 / 版本:** DNS Server Discovery Via LDAP Query · `low` · `2023-09-18`
- **OCSF v1.4.0 映射:** `class_uid=[4003]` · `field_mappings={"Image": "actor.process.file.path", "QueryName": "query.hostname"}` · `static_data_coverage=True`
- **指标:** `TP=2, FP=0, FN=0, TN=2, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-41-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): _ldap. SRV query from SharpHound.exe in C:\Users\Public\.
  - `gt-41-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): _ldap. SRV query from D:\Temp\adrecon.exe.
  - `gt-41-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): Excluded by filter_main_generic (:\Windows\).
  - `gt-41-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): Boundary: missing Image excluded by filter_main_null (Image: null).

### #42 `dns_query_win_regsvr32_dns_query.yml` (`36e037c4-c228-4866-b6a3-48eb292b9955`)
- **标题 / 等级 / 版本:** DNS Query Request By Regsvr32.EXE · `medium` · `2023-09-18`
- **OCSF v1.4.0 映射:** `class_uid=[4003]` · `field_mappings={"Image": "actor.process.file.path"}` · `static_data_coverage=True`
- **指标:** `TP=2, FP=0, FN=0, TN=2, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-42-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): System32 regsvr32.exe performing DNS resolution.
  - `gt-42-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): SysWOW64 REGSVR32.EXE case-insensitive match.
  - `gt-42-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): svchost.exe DNS query.
  - `gt-42-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): Does not end with '\regsvr32.exe'.

### #43 `net_dns_mal_cobaltstrike.yml` (`2975af79-28c4-4d2f-a951-9095f229df29`)
- **标题 / 等级 / 版本:** Cobalt Strike DNS Beaconing · `critical` · `2022-10-09`
- **OCSF v1.4.0 映射:** `class_uid=[4003]` · `field_mappings={"query": "query.hostname"}` · `static_data_coverage=True`
- **指标:** `TP=2, FP=0, FN=0, TN=2, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-43-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): Starts with default Cobalt Strike DNS beacon prefix 'aaa.stage.'.
  - `gt-43-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): Contains '.stage.123456.' (selection2).
  - `gt-43-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): Normal internal 'stage.' subdomain.
  - `gt-43-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): 'post.1' is not at start of hostname.

### #44 `net_dns_susp_txt_exec_strings.yml` (`8ae51330-899c-4641-8125-e39f2e07da72`)
- **标题 / 等级 / 版本:** DNS TXT Answer with Possible Execution Strings · `high` · `2021-11-27`
- **OCSF v1.4.0 映射:** `class_uid=[4003]` · `field_mappings={"answer": "answers.rdata", "record_type": "query.type"}` · `static_data_coverage=False`
- **指标:** `TP=2, FP=0, FN=0, TN=5, ERROR=0` · `Precision=1.0000, Recall=1.0000, F1=1.0000, FPR=0.0000`
- **逐用例结果:**
  - `gt-44-tp-1` (expected=`True` → outcome=`MATCH`, **TP**): TXT record with 'IEX' in second dns_answer.rdata element.
  - `gt-44-tp-2` (expected=`True` → outcome=`MATCH`, **TP**): TXT record with 'cmd.exe' in dns_answer.rdata.
  - `gt-44-tn-1` (expected=`False` → outcome=`NO_MATCH`, **TN**): query.type is 'A' rather than 'TXT'.
  - `gt-44-tn-2` (expected=`False` → outcome=`NO_MATCH`, **TN**): Benign SPF TXT record in rdata.
  - `gt-44-tn-3-sibling-only` (expected=`False` → outcome=`NO_MATCH`, **TN**): Target strings ('IEX', 'cmd.exe', 'Invoke-') appear only in sibling attributes (class, type, flags), NOT in rdata.
  - `gt-44-tn-4-empty-answers` (expected=`False` → outcome=`NO_MATCH`, **TN**): Empty answers array [] must not match.
  - `gt-44-tn-5-missing-answers` (expected=`False` → outcome=`NO_MATCH`, **TN**): Missing answers field must not match.
