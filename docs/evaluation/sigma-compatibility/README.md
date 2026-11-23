# ProvLoom Sigma Detection Compatibility & Correctness Evaluation (OCSF v1.4.0)

> **唯一指标数据源 (Single Source of Truth):** 本目录所有表格与汇总数字均由 `tests/evaluation/run_evaluation.py` 从 `evaluation-results.json` 自动生成，零人工抄录。

## 1. 运行环境与固定规范版本

| 项目 | 实测值 / 锁定版本 |
| :--- | :--- |
| 操作系统 / Python | `macOS-27.2.1-arm64-arm-64bit-Mach-O` / Python `3.13.18` |
| PostgreSQL 版本 | `PostgreSQL 16.16 on aarch64-unknown-linux-musl, compiled by gcc (Alpine 15.2.0) 15.2.0, 64-bit` |
| 核心依赖版本 | `pySigma 1.5.1` · `pySigma-pipeline-ocsf 0.1.2` · `SQLAlchemy 2.1.9` · `psycopg 3.3.9` |
| 基线对比 Commit | `0944102a339e1d6df928ea16442494232f6e5e22` (branch `feat/detection-layer-v0.2`) |
| **当前评测代码 Commit** | `506cc0d620bbe6489d4f79297a2ada934103c3e4` (`working_tree_dirty=False`) |
| 代码变更补丁 SHA-256 (`src/ + configs/`) | `a40e7225e758b0e02998a3e2c8f4697e6826ed53593b551b8f7d62e58bfbb883` |
| **OCSF Schema 锁定版本** | **`v1.4.0`** (`tag: 1.4.0`, commit `6109cc5e834c1adfee67dda6c9bcfa5e37f79012`) |
| SigmaHQ 规则集 Commit | `698f0912f571d5fac3bf8c51f5421139834a011` (`45` 条社区原版 YAML，零修改) |
| 公开数据集 Commits | `ocsf/examples@ce0589ece917` · `OTRF@d9d40ef123d2` · `Splunk@5879f5423e6c` |

## 2. 规则五阶段兼容性汇总（45 条 SigmaHQ 社区规则）

> **静态覆盖与端到端覆盖分离说明：** `Static Data Coverage` 仅衡量内置 `configs/mappings/*.yaml` 是否提取规则引用字段（`21/45`）；真实原始日志端到端结果见《正确性报告》第 4 节。

| 指标 | 基线 (`0944102`) | 修正后 (`OCSF v1.4.0`) | 计算口径 |
| :--- | :---: | :---: | :--- |
| **Parse Success Rate** | `45/45` (`100.00%`) | **`45/45` (`100.00%`)** | 解析成功规则 / 总规则 (`45`) |
| **Mapping Coverage** | `33/45` (`73.33%`) | **`32/45` (`71.11%`)** | 字段与事件类完整映射至 OCSF `v1.4.0` 标量叶子路径 / 可评估规则 (`45`) |
| **Compile Success Rate** | `32/33` (`96.97%`) | **`32/32` (`100.00%`)** | 参数化 SQL 编译成功 / 可映射规则 |
| **Execution Success Rate** | `31/32` (`96.88%`) | **`32/32` (`100.00%`)** | PostgreSQL 16 零异常执行 / 可编译规则 |
| **Full Compatibility (Standard OCSF v1.4.0)** | `31/45` (`68.89%`) | **`32/45` (`71.11%`)** | 标准 OCSF `v1.4.0` 事件层全流程成功 / 总规则 (`45`) |
| **Static Built-in Raw Mapper Coverage** | `20/45` (`44.44%`) | **`21/45` (`46.67%`)** | 规则执行成功且 `DATA_COVERAGE=True` / 总规则 (`45`) |

## 3. 检测正确性汇总（同一规则、同一标准 OCSF v1.4.0 用例、同一四态口径）

所有执行结果严格区分四态：**`MATCH`**、**`NO_MATCH`**、**`ERROR`**（编译/SQL 执行异常，**绝不计入 `TN`**）、**`UNSUPPORTED`**（能力检查拒绝，单列统计）。

| 测试套件 | 版本 | 总用例 | 已执行 (`MATCH`/`NO_MATCH`) | `ERROR` (正/负) | `UNSUPPORTED` | TP | FP | FN | TN | Precision | Recall (已执行) | F1 (已执行) | Recall (含 `ERROR` 漏报) | F1 (含 `ERROR`) | FPR |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **15 维语义套件 (`D01..D15`)** | 基线 `0944102` | 59 | 51 | 4 (2/2) | 4 | 24 | 1 | 1 | 25 | 0.9600 | 0.9600 | 0.9600 | 0.8889 | 0.9231 | 0.0385 |
| **15 维语义套件 (`D01..D15`)** | **修正后 `v1.4.0`** | **59** | **59** | **0** | **0** | **30** | **0** | **0** | **29** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **0.0000** |
| **32 条可执行 SigmaHQ 规则** | 基线 `0944102` | 133 | 125 | 4 (2/2) | 4 | 58 | 1 | 2 | 64 | 0.9831 | 0.9667 | 0.9748 | 0.9355 | 0.9587 | 0.0154 |
| **32 条可执行 SigmaHQ 规则** | **修正后 `v1.4.0`** | **133** | **133** | **0** | **0** | **64** | **0** | **0** | **69** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **0.0000** |
| **合计标准 OCSF v1.4.0 执行集** | 基线 `0944102` | 192 | 176 | 8 (4/4) | 8 | 82 | 2 | 3 | 89 | 0.9762 | 0.9647 | 0.9704 | 0.9213 | 0.9480 | 0.0220 |
| **合计标准 OCSF v1.4.0 执行集** | **修正后 `v1.4.0`** | **192** | **192** | **0** | **0** | **94** | **0** | **0** | **98** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **0.0000** |

- **单独统计套件（不混入标准执行集）：**
  1. **不支持规则拒绝审计 (`#25` `file_event_win_office_macro_files_from_susp_process.yml`, 3 用例)：** 基线 `0944102` 因上游 `ParentImage -> file.name` 串扰被误标为 `EXECUTABLE`（产生 `TP=1, FP=1, FN=1`）；修正后 `3/3` 用例显式归为 **`UNSUPPORTED`**（拒绝原因：`Unmapped Sigma field: 'ParentImage'`）。
  2. **非法输入健壮性测试 (`robustness_oracle.json`, 4 用例)：** 全部违反 OCSF `v1.4.0` schema，执行结果 `4/4 NO_MATCH`、`0 ERROR`。
  3. **历史 OCSF `v1.3.0` 输入兼容测试 (`legacy_compat_oracle.json`, 4 用例)：** 兼容重放前的 `answers` 字符串数组与标量字符串，`TP=2, TN=2, FP=0, FN=0`。

## 4. 完整复现命令与交付物清单

```bash
make db-up
PROVLOOM_DATABASE_URL=postgresql+psycopg://provloom:provloom@127.0.0.1:5432/provloom .venv/bin/alembic upgrade head
make lint && make typecheck && .venv/bin/mypy --strict tests
PROVLOOM_EVAL_PG_URL=postgresql+psycopg://provloom:provloom@127.0.0.1:5432/provloom .venv/bin/pytest tests/unit/ tests/integration/ tests/acceptance/ -v
PROVLOOM_EVAL_PG_URL=postgresql+psycopg://provloom:provloom@127.0.0.1:5432/provloom .venv/bin/pytest tests/evaluation/ -v
git diff 0944102a339e1d6df928ea16442494232f6e5e22..HEAD -- src/ configs/ > docs/evaluation/sigma-compatibility/src-and-configs.patch
PROVLOOM_EVAL_PG_URL=postgresql+psycopg://provloom:provloom@127.0.0.1:5432/provloom PYTHONPATH=src:. .venv/bin/python tests/evaluation/run_evaluation.py
```

- `evaluation-results.json`：唯一机器可读逐用例结果、环境指纹、输入守恒账本与性能原始数据
- `src-and-configs.patch`：相对基线 `0944102` 的 `src/` 与 `configs/` 完整代码补丁
- `rule-inventory.csv`：45 条社区规则元数据、SHA-256 与五阶段状态清单
- `compatibility-report.md`：OCSF `v1.4.0` 升级变更、Schema/枚举/约束校验范围与前后状态迁移表
- `correctness-report.md`：逐规则指标、Oracle 修正审计记录、对账说明与公开数据集守恒表
- `unsupported-rules.md`：13 条显式拒绝规则与 11 条原始日志字段缺口分类
- `performance-report.md`：10,000 事件首次冷执行 vs 幂等重跑吞吐与 5x 确定性报告
- `recommendations.md`：后续数据层原始日志接入与索引演进建议

## 5. 已验证范围与已知限制 (Supported Scope & Known Limitations)

- **已验证能力：**
  1. **OCSF `v1.4.0` 严格结构、枚举与约束契约：** 基于官方 `1.4.0`（`6109cc5e834c`）校验全部 192 条标准合成事件（59 语义 + 133 SigmaHQ）、9 个内置映射事件类（`1001, 1007, 3002, 4001, 4003, 5001, 6001, 6002, 6003`）、`0` 兜底类与 `1009` 脚本类（含深层合并 `enum`、继承 `at_least_one`/`just_one` 约束、`metadata.profiles` 成员及 `web_resources[].name` 修复），结构/枚举/约束错误数 `0`。
  2. **三值逻辑（3VL）与缺失字段 / `NOT` 语义一致性：** 覆盖缺失字段、JSON `null`、空字符串、空数组与 `[null, {"rdata": null}]`，PostgreSQL 16 与 SQLite 查询结果 `100%` 一致。
  3. **同数组元素约束：** DNS `answers[].rdata`（含历史字符串数组兼容分支）与文件/进程哈希（`md5`/`sha1`/`sha256`/`sha512` 重写为同一 `hashes[]` 元素内的 `algorithm_id + value` 相关子查询）杜绝跨元素与兄弟属性误命中。
  4. **社区 SigmaHQ 评测汇总：** 45 条社区原版规则 `Parse 45/45`、`Mapping 32/45`、`Compile 32/32`、`Execution 32/32`，192 条标准用例合并 `TP=94, FP=0, FN=0, TN=98, ERROR=0, UNSUPPORTED=0`。
- **明确不支持与已知限制：**
  1. **显式拒绝的 13 / 45 条 SigmaHQ 规则：** 包含 `|fieldref`、`|cidr`、`|base64offset`、`|expand`、未接入日志源（`ps_classic_start`、Kerberos `4768`、无 category 的 Zeek DNS）及 `file_event` 跨类字段 `ParentImage`（全部显式标为 `UNSUPPORTED`，不静默降级）。
  2. **静态原始日志覆盖缺口（`11 / 32` 条可执行规则 `DATA_COVERAGE=False`）：** 如 `OriginalFileName`、`CurrentDirectory`、`DestinationHostname`、`QueryType` 及 PowerShell `4104 -> 1009` 原始映射尚未接入；原始公开数据集中 Sysmon EID 22 缺失端点与 OTRF `Hostname` 别名如实记为源端约束缺口，不在归一化阶段伪造字段。
  3. **架构边界：** 仅支持单事件与结构化 1-hop 关系检测，不支持多跳图模式、Sigma Correlation、`timeframe`、UEBA 或自动 SOAR 响应。
