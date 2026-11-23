# 阶段一至三：OCSF v1.4.0 契约升级与五阶段兼容性报告

## 1. OCSF `v1.3.0` → `v1.4.0` 契约升级与 Schema 校验说明

- **锁定规范版本：** 官方 `https://github.com/ocsf/ocsf-schema` tag `1.4.0`（commit `6109cc5e834c1adfee67dda6c9bcfa5e37f79012`，`version.json = "1.4.0"`）。
- **离线校验工具与范围：**
  - 导出脚本将官方 `1.4.0` 的 `dictionary.json`、`categories.json`、`events/**`、`objects/**`、`profiles/**` 与 `extensions/{linux,windows}/**` 编译为确定性 Schema 快照 `tests/evaluation/fixtures/ocsf_v1_4_0_schema.json`（含深层合并 `enum` 与继承 `constraints`），由 `tests/evaluation/ocsf_validator.py` 执行严格校验（含枚举、Profile 成员与 `at_least_one`/`just_one` 约束）。
  - **校验覆盖范围：**
    1. **标准合成事件集（`192` 条 = `59` 语义用例 + `133` SigmaHQ 用例）：** 以 `allow_provloom_metadata_original_uid=False, check_enums=True, check_constraints=True` 严格校验 `metadata.version == "1.4.0"`、`class_uid`/`category_uid`/`type_uid` 一致性、枚举值、Profile 成员、类与嵌套对象 `constraints`、必填项及未知属性白名单，**错误数 `0/192`**。
    2. **全部 9 个既有内置事件类（`1001, 1007, 3002, 4001, 4003, 5001, 6001, 6002, 6003`）+ `0` 兜底类 + `1009` 脚本类：** 经 `YamlOcsfMapper` / `FallbackNormalizer` 产出的 `NormalizedEvent` 全部满足 `ocsf_version == metadata.version == "1.4.0"`、`metadata.profiles` 自动声明与 `web_resources[].name` 约束，并通过严格 Schema 校验（`metadata.original_uid` 作为 `AGENTS.md` §2.2 溯源不变量显式声明）。
    3. **编译器字段目录一致性：** 单元测试强制校验 `KNOWN_OCSF_V14_FIELDS`、`DEFAULT_PROVLOOM_COVERED_FIELDS` 与 `configs/mappings/*.yaml` 中的每一个字段路径在 OCSF `v1.4.0` 中均存在且落于**标量叶子属性**（禁止如裸 `answers` 或裸 `script.script_content` 等对象节点直接作为文本提取路径）。

## 2. 关键结构映射与查询语义修正（对比上游 `pySigma-pipeline-ocsf 0.1.2`）

| 领域 / 规则 | 上游或旧映射问题 | 修正后 OCSF `v1.4.0` 标准路径与 SQL 语义 |
| :--- | :--- | :--- |
| **DNS Answers (`4003`, `D15`, `#44`)** | 旧实现映射至 `answers` 并用 `jsonb_array_elements_text` 序列化整个 `dns_answer` JSON 对象，导致兄弟属性（如 `type`/`class`/`flags`）中的字符串误命中 | 映射至 **`answers.rdata`**；SQL 对 JSON 对象元素仅提取 `elem ->> 'rdata'`（同时单独保留重放前历史字符串数组/标量兼容分支），空数组/缺失字段在 `NOT` 下保持布尔 `False`（非 SQL `NULL`） |
| **File / Process Hashes (`1001`, `1007`)** | 裸 `sha256 -> *.hashes.value` 且 `AND` 条件生成各自独立的 `EXISTS` 子查询，导致 MD5 值在元素 0、SHA-256 标记在元素 1 时跨元素误命中 | `_ScopedHashAlgorithmTransformation` 将 `md5`/`sha1`/`sha256`/`sha512` 展开为同数组 `(algorithm_id, value)` 组合，并在后端融合为**单个相关 `EXISTS` 子查询**约束同一 `fingerprint` 元素（Custom Rule `all` 同路径同样融合） |
| **Script Activity (`1009`, `#17`, `#18`)** | `1.3.0` 无 `1009` 类；且上游 `pySigma-pipeline-ocsf 0.1.2` 将 `ScriptBlockText`/`Payload` 错误映射至 `long_string` 对象节点 `script.script_content` | 升级至 `1.4.0` 标准 `script_activity (1009)`，显式映射至 **`script.script_content.value`**（`objects/long_string.json` 必填标量属性） |
| **Process `internal_name` / `working_directory` (`#01,#02,#06,#09,#12`)** | 在 `1.3.0` 中不存在，存在契约错位 | 在 `1.4.0` `objects/file.json` 与 `objects/process.json` 中均为正式标准标量属性（注：内置 `sysmon_process_create_1007.yaml` 尚未提取，故静态 `DATA_COVERAGE=False`） |
| **`file_event` `ParentImage` (`#25`)** | 上游 `ocsf_pipeline` 将 `ParentImage` 错误重写为 `file.name` | 阻断跨类别污染，显式拒绝为 `UNSUPPORTED` |

## 3. 基线 (`0944102`) → 修正后 (`OCSF v1.4.0`) 状态与映射变化单列展示

| # | 规则文件 | 基线状态与表现 (`0944102`) | 修正后状态与表现 (`v1.4.0`) | 字段映射变化 |
| :---: | :--- | :--- | :--- | :--- |
| 25 | `file_event_win_office_macro_files_from_susp_process.yml` | `EXECUTABLE` (误映射 `ParentImage -> file.name`，审计集 `FP=1, FN=1`) | **`UNSUPPORTED`** (`3/3` 用例显式拒绝) | `{"Image": "actor.process.file.path", "ParentImage": "file.name", "TargetFilename": "file.path"}` → 显式拒绝 `Unmapped Sigma field: 'ParentImage'` |
| 08 | `proc_creation_win_sysinternals_procdump_lsass.yml` | `UNSUPPORTED` (TP=0, FP=0, FN=0, ERR=0) | `EXECUTABLE` (TP=2, FP=0, FN=0, ERR=0) | `{"CommandLine": "process.cmd_line"}` → `{"CommandLine": "process.cmd_line"}` |
| 12 | `proc_creation_win_csc_susp_parent.yml` | `ERROR` (TP=0, FP=0, FN=0, ERR=4) | `EXECUTABLE` (TP=2, FP=0, FN=0, ERR=0) | `{"Image": "process.file.path", "OriginalFileName": "process.file.internal_name", "ParentCommandLine": "process.parent_process.cmd_line", "ParentImage": "process.parent_process.file.path"}` → `{"Image": "process.file.path", "OriginalFileName": "process.file.internal_name", "ParentCommandLine": "process.parent_process.cmd_line", "ParentImage": "process.parent_process.file.path"}` |
| 17 | `posh_ps_potential_invoke_mimikatz.yml` | `EXECUTABLE` (TP=2, FP=0, FN=0, ERR=0) | `EXECUTABLE` (TP=2, FP=0, FN=0, ERR=0) | `{"ScriptBlockText": "script.script_content"}` → `{"ScriptBlockText": "script.script_content.value"}` |
| 18 | `posh_pm_invoke_obfuscation_clip.yml` | `EXECUTABLE` (TP=0, FP=0, FN=2, ERR=0) | `EXECUTABLE` (TP=2, FP=0, FN=0, ERR=0) | `{"Payload": "script.script_content"}` → `{"Payload": "script.script_content.value"}` |
| 44 | `net_dns_susp_txt_exec_strings.yml` | `EXECUTABLE` (TP=2, FP=1, FN=0, ERR=0) | `EXECUTABLE` (TP=2, FP=0, FN=0, ERR=0) | `{"answer": "answers", "record_type": "query.type"}` → `{"answer": "answers.rdata", "record_type": "query.type"}` |
