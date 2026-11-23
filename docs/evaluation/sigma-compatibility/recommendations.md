# 未解决问题与后续演进建议（不阻塞当前 OCSF v1.4.0 契约）

## 1. 当前已知范围边界与未解决问题

1. **原始日志解析与 YAML 映射覆盖缺口（`11 / 32` 条可执行规则 `DATA_COVERAGE=False`）：**
   - `configs/mappings/sysmon_process_create_1007.yaml` 尚未提取 Sysmon `OriginalFileName -> process.file.internal_name`、`CurrentDirectory -> process.working_directory`、`Description -> process.file.desc`（影响 `#01, #02, #06, #09, #12` 的原始日志分支，其中 `#09` 完全依赖 `OriginalFileName`）。
   - 尚未内置 Windows PowerShell Operational `EventID 4104 / 4103` 解析器与 `1009` 映射配置（影响 `#17, #18` 原始日志端到端接入）。
   - `sysmon_network_connect_4001.yaml` / `auth_logon_3002.yaml` / `sysmon_dns_4003.yaml` 尚未映射 `DestinationHostname`、`WorkstationName`、`QueryType`（影响 `#29, #30, #36, #44` 的原始日志字段提取）。
   - OTRF / NXLog 导出的 Sysmon JSONL 使用 `Hostname` 而非 `Computer`，当前 `sysmon` 解析/映射仅绑定 `Computer`。
2. **明确继续显式拒绝的 Sigma 能力（`13 / 45` 条 `UNSUPPORTED`）：**
   - 高级修饰符：`SigmaFieldReferenceModifier` (`|fieldref`)、`SigmaCIDRModifier` (`|cidr`)、`SigmaBase64OffsetModifier` (`|base64offset`)、`SigmaExpandModifier` (`|expand`)。
   - 未映射日志源与专有字段：Windows `ps_classic_start`、Kerberos `4768`、Zeek 无 `category` 的 `service: dns`、Sysmon `Initiated` / `Product` / `LogonProcessName` / `SubjectUserSid` / `KeyLength`、以及 `file_event` 上的非 Sysmon 字段 `ParentImage`。
   - 超出 PostgreSQL POSIX ARE `DUPMAX=255` 的多字符分组量词（如 `(?:abc){1,300}`）以及 Sigma Correlation / `timeframe` 聚合规则（MVP 范围外）。
3. **工程性能特征：**
   - 当前单事件 SQL 查询对 JSONB 文本路径使用 `lower(ocsf_payload #>> ...) LIKE ...` 顺序扫描租户时间窗内的目标 `class_uid` 分区；在 10,000 事件规模下单规则 P50 约数毫秒，若扩展至百万级事件建议按高频路径增加 `pg_trgm` / 表达式 GIN 索引。

## 2. 下一阶段优先级建议

- **P1（补齐原始日志映射）：** 扩展 `sysmon_process_create_1007.yaml`（`OriginalFileName`、`CurrentDirectory`、`Hostname` 别名）与 `sysmon_dns_4003.yaml`（`QueryType`），新增 PowerShell `4104 -> 1009 (script.script_content.value)` 解析器与 YAML 映射。
- **P2（高价值修饰符支持）：** 基于 PostgreSQL 原生 `inet <<= cidr` 支持 `|cidr`（激活 `#32, #38`），基于三偏移子串支持 `|base64offset`（激活 `#16`），基于同事件双列对比支持 `|fieldref`（激活 `#11, #26`）。
