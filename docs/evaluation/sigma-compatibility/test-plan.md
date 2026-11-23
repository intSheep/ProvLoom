# ProvLoom Sigma 兼容性与正确性评测方案（OCSF v1.4.0）

## 1. 目标与规范基线

- **OCSF 规范版本：** `v1.4.0`（官方 `https://github.com/ocsf/ocsf-schema` tag `1.4.0`，commit `6109cc5e834c1adfee67dda6c9bcfa5e37f79012`）。
- **Schema 校验器：** `tests/evaluation/ocsf_validator.py`（基于离线快照 `tests/evaluation/fixtures/ocsf_v1_4_0_schema.json`），强制校验全部 `192` 条标准合成事件（`59` 语义 + `133` SigmaHQ）与全部 `9` 个内置映射事件类（`1001, 1007, 3002, 4001, 4003, 5001, 6001, 6002, 6003`）+ `0` + `1009`。
- **Sigma 修饰符规范：** Sigma Modifiers Specification `v2.1.0` 与 `pySigma 1.5.1`。
- **社区规则基线：** `SigmaHQ/sigma` commit `698f0912f571d5fac3bf8c51f5421139834a011`（45 条原版 YAML，零修改）。

## 2. 测试数据集分层设计

1. **标准 OCSF `v1.4.0` 执行集（`192` 用例）：**
   - `tests/evaluation/rule_semantics/semantic_oracle.json`：`15` 个语法/修饰符维度，`59` 条用例（含 `answers[].rdata` 精确/包含/否定/多元素/空数组/缺失/兄弟属性反例，`plain` vs `|base64` vs `|cased` vs `|base64|cased` 独立大小写用例，以及 JSON `null` 下的 `|exists`）。
   - `tests/evaluation/ground_truth/sigmahq_ground_truth.json`：`32` 条受支持社区规则，`133` 条用例（含 `1009` `script.script_content.value` 与 `4003` `answers[].rdata` 兄弟属性隔离反例）。
2. **不支持规则拒绝审计集（`3` 用例，单独统计）：**
   - `tests/evaluation/ground_truth/unsupported_audit_oracle.json`（`#25` `ParentImage` 拒绝审计）。
3. **非法输入健壮性测试集（`4` 用例，单独统计）：**
   - `tests/evaluation/ground_truth/robustness_oracle.json`（刻意违反 OCSF `v1.4.0` 类型契约，验证零 SQL 崩溃且返回 `NO_MATCH`）。
4. **历史 OCSF `v1.3.0` 输入兼容测试集（`4` 用例 + 重放转换测试，单独统计）：**
   - `tests/evaluation/ground_truth/legacy_compat_oracle.json`（验证重放前 `answers` 字符串数组/标量兼容路径，以及 `trigger_replay` 在保持 `raw_events` 不变的前提下将派生事件升级为 `1.4.0` `answers[].rdata`）。
5. **公开真实数据集：** `ocsf/examples`、`OTRF Security-Datasets`、`Splunk Attack Data`（未知背景流量一律记为 `UNKNOWN`，绝不计入 `TN`）。

## 3. 四态统计口径

每个用例输出唯一状态：`MATCH`、`NO_MATCH`、`ERROR`、`UNSUPPORTED`。`ERROR` 绝不计入 `TN`；`UNSUPPORTED` 单独列示；所有报告表格均由 `tests/evaluation/run_evaluation.py` 从 `evaluation-results.json` 自动生成。
