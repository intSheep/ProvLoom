# ProvLoom Detection Layer PRD

**版本：** v0.2  
**项目：** ProvLoom  
**模块：** Detection & Signal Generation  
**性质：** 现有项目功能扩展  
**目标：** 基于 OCSF 标准化事件和 Provenance Graph，发现值得进一步调查的可疑行为，并为 APT Investigation Agent 提供高质量调查线索。

---

## 1. 项目背景

ProvLoom 当前已经具备安全数据处理能力：

- 多源日志接入。
- OCSF 标准化。
- 实体识别与身份归一化。
- 实体交互关系提取。
- Provenance Graph 构建。
- 原始日志与关系证据追溯。
- 统一查询 API。
- Web 数据查看与调试控制台。

此前系统主要解决：**如何将异构安全数据转换为统一、可查询、可追溯的安全事实。**

本次扩展解决：**如何从大量安全事实中发现值得关注的可疑行为，并将其转化为后续调查的入口。**

Detection Layer 不负责最终判定攻击，而是负责发现可疑信号。最终攻击研判、假设验证和攻击链重建由后续 APT Investigation Agent 负责。

## 2. 产品定位与职责边界

ProvLoom 扩展为三个逻辑层次：

### 2.1 Data Layer（发生了什么？）

- OCSF 标准化事件、实体识别、实体关系、时间和证据追溯、统一查询服务。

### 2.2 Detection Layer（什么行为值得关注？）

- 单事件规则检测、基础实体关系检测、规则管理、检测结果生成、初步线索关联、Signal 管理。

### 2.3 Investigation Agent（这些行为是否构成攻击？— 外部下游组件）

- 关联不同可疑线索、生成攻击假设、识别证据缺口、规划调查行动、查询相关事件和关系、寻找支持证据和反证、形成攻击链和调查报告。

Detection Layer 不应直接输出已经确认的攻击结论。

## 3. 整体架构

```text
                 ProvLoom
                     |
          +----------+----------+
          |                     |
       Data Layer           Detection Layer
          |                     |
     OCSF Events           Rule Management
          |                     |
     Entity Store          Sigma Parser
          |                     |
     Relation Graph       OCSF Pipeline
          |                     |
     Evidence Store       SQL Detection Backend
          |                     |
          |               Graph Relation Matcher
          |                     |
          +----------+----------+
                     |
                 Rule Match
                     |
                Signal Manager
                     |
              Candidate Group
                     |
           Future Investigation Agent
```

Detection Layer 与现有 Data Layer 位于同一个项目和部署单元中，使用独立的领域模型和模块边界，不引入独立 Detection 微服务。

## 4. 模块结构

```text
src/provloom/
├── detection/
│   ├── domain/
│   │   ├── rule.py
│   │   ├── rule_match.py
│   │   ├── signal.py
│   │   └── candidate_group.py
│   ├── rules/
│   │   ├── sigma/
│   │   ├── custom/
│   │   └── registry.py
│   ├── compiler/
│   │   ├── sigma_parser.py
│   │   ├── ocsf_pipeline.py
│   │   └── postgres_backend.py
│   ├── matcher/
│   │   ├── event_matcher.py
│   │   └── relation_matcher.py
│   ├── signals/
│   │   ├── generator.py
│   │   ├── deduplicator.py
│   │   └── candidate_grouper.py
│   └── service.py
└── api/
    └── v1/
        └── detection.py
```

## 5. 检测规则来源与兼容性

- **Sigma（主要单事件知识源）**：基于 `pySigma` 与 `pySigma-pipeline-ocsf`（结合 ProvLoom OCSF v1.4.0 规范映射对齐，校正如 `answers.rdata`、`script.script_content.value` 等嵌套对象路径），优先覆盖 `process_creation`、`ps_script` / `ps_module`、`file_event` / `file_access` / `file_change`、`network_connection`、`authentication`、`dns` / `dns_query`、`process_access`。保留原始 YAML、ID、版本、来源路径、ATT&CK 标签、严重程度与兼容性结果。
- **ProvLoom Custom Rules**：结构化 YAML 表达，支持 OCSF 原生字段条件与一跳实体关系检测，禁止任意 Python 代码或任意 SQL。
- **五阶段兼容性报告**：明确区分 `PARSE_SUCCESS`、`MAPPING_SUCCESS`、`DATA_COVERAGE`、`COMPILE_SUCCESS`、`EXECUTION_SUCCESS`。不支持的字段、修饰符或 Correlation 语义必须显式报告，禁止静默忽略。

## 6. 核心模型与不变量

- **RuleMatch**：永久保留的单次规则命中记录，幂等去重（重复执行或重复导入同事件不产生重复 `RuleMatch`），关联 OCSF 事件、实体与原始日志证据引用。
- **Signal**：可关联一个或多个 `RuleMatch` 的可疑线索（生命周期：`NEW` / `OPEN` / `ACKNOWLEDGED` / `RESOLVED` / `SUPPRESSED`），状态仅表示线索处理进度，绝不代表攻击定性，也不跨不同实体错误合并。
- **CandidateGroup**：基于可配置确定性条件（共享归一实体、一跳 `DETERMINISTIC` 关系及时间窗）生成的候选分组，保留完整 `grouping_basis` 与未解决歧义提示，不修改客观事实图。

## 7. API、Web 控制台与可观测性

- **Detection API (`/api/v1/detection/*`)**：规则管理（列表、详情、启用、禁用、校验、导入、沙盒测试）、检测执行（单规则、批量、执行记录）、`RuleMatch` 查询、`Signal` 查询与状态更新、`CandidateGroup` 查询。全部继承 `AccessScope`、`TimeRange`、分页上限与执行权限控制。
- **Web Detection Console (`/detection`)**：规则管理、规则测试（展示原始 YAML、解析结果、OCSF 字段映射、参数化 SQL、匹配结果、耗时与错误）、`RuleMatch` 浏览器、`Signal` 浏览器（支持一键跳转实体检查器与溯源图谱工作台）、`CandidateGroup` 浏览器。
- **可观测性指标**：`detection_rules_total`、`detection_rules_supported_total`、`detection_rules_unsupported_total`、`detection_executions_total`、`detection_matches_total`、`detection_execution_duration_seconds`、`signals_created_total`、`signals_deduplicated_total`、`signals_aggregated_total`、`candidate_groups_created_total` 及阶段失败计数。

## 8. MVP 验收标准（AC-01 .. AC-12）

- **AC-01**：能够导入 Sigma YAML。
- **AC-02**：能够识别不支持的 Sigma 规则语义。
- **AC-03**：能够将支持的 Sigma 规则映射到 OCSF 字段。
- **AC-04**：能够在 PostgreSQL / SQL Backend 中执行单事件检测。
- **AC-05**：能够执行基础一跳实体关系检测。
- **AC-06**：每次规则命中都生成可追溯 `RuleMatch`。
- **AC-07**：`Signal` 能关联一个或多个 `RuleMatch`。
- **AC-08**：重复事件不会产生重复 `RuleMatch`。
- **AC-09**：`CandidateGroup` 能保留成员及聚合依据。
- **AC-10**：检测结果能够追溯到 OCSF 事件和原始日志。
- **AC-11**：Web 可以查看规则、命中结果和 `Signal`。
- **AC-12**：所有检测查询遵守权限和执行限制。
