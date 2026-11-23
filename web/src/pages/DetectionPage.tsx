import type { ColumnDef } from "@tanstack/react-table";
import { useId, useMemo, useRef, useState, type FormEvent, type KeyboardEvent } from "react";
import { useNavigate } from "react-router-dom";
import { detectionApi } from "../api/client";
import {
  useCandidateGroupMembersQuery,
  useCandidateGroupsQuery,
  useDetectionRuleDetailQuery,
  useDetectionRulesQuery,
  useExecuteBatchMutation,
  useImportRuleMutation,
  useMetricsQuery,
  useRuleMatchesQuery,
  useSignalEvidenceQuery,
  useSignalMatchesQuery,
  useSignalsQuery,
  useTestRuleMutation,
  useToggleRuleMutation,
  useUpdateSignalStatusMutation,
} from "../api/hooks";
import type {
  CandidateGroupDto,
  DetectionRuleDetailDto,
  DetectionRuleDto,
  DetectionType,
  RuleCompatibilityDto,
  RuleMatchDto,
  RuleSeverity,
  RuleSource,
  RuleStatus,
  RuleTestResponseDto,
  SignalDto,
  SignalStatus,
} from "../api/types";
import { DataTable } from "../components/common/DataTable";
import { JsonViewer } from "../components/common/JsonViewer";
import {
  CertaintyPill,
  RuleSeverityPill,
  RuleStatusPill,
  SignalStatusPill,
} from "../components/common/StatusPill";
import { useConsoleContext } from "../state/ConsoleContext";

type DetectionTab = "signals" | "groups" | "matches" | "rules" | "sandbox";

const TABS: { id: DetectionTab; label: string }[] = [
  { id: "signals", label: "Signal 调查线索" },
  { id: "groups", label: "CandidateGroup 候选组" },
  { id: "matches", label: "RuleMatch 命中记录" },
  { id: "rules", label: "规则库管理" },
  { id: "sandbox", label: "规则编译与测试沙盒" },
];

const SIGNAL_STATUSES: SignalStatus[] = [
  "NEW",
  "OPEN",
  "ACKNOWLEDGED",
  "RESOLVED",
  "SUPPRESSED",
];

const SEVERITIES: RuleSeverity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"];

const SAMPLE_SIGMA_YAML = `title: PowerShell Suspicious Staging Flag Test
id: 99999999-8888-4777-a666-555555555555
version: 1.0.0
description: Sandbox test rule matching PowerShell non-interactive or temp script execution.
level: high
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - '-nop'
      - 'EncodedCommand'
  filter_benign:
    CommandLine|contains: 'Get-Date'
  condition: selection and not filter_benign
`;

function CompatibilityStages({ compat }: { compat: RuleCompatibilityDto }) {
  const items: { label: string; state: boolean | null }[] = [
    { label: "PARSE", state: compat.parse_success },
    { label: "MAP", state: compat.mapping_success },
    { label: "COV", state: compat.data_coverage },
    { label: "SQL", state: compat.compile_success },
    { label: "EXEC", state: compat.execution_success },
  ];
  return (
    <div className="flex flex-wrap gap-1">
      {items.map((it) => {
        const cls =
          it.state === true
            ? "border-emerald-500/50 text-emerald-500 bg-emerald-500/10"
            : it.state === false
              ? "border-red-500/50 text-red-500 bg-red-500/10"
              : "border-slate-500/40 text-[var(--pl-text-muted)] bg-[var(--pl-surface-alt)]";
        const mark = it.state === true ? "✓" : it.state === false ? "✗" : "·";
        return (
          <span
            key={it.label}
            className={`inline-flex items-center gap-0.5 rounded border px-1.5 py-0.5 text-[10px] font-mono-code ${cls}`}
          >
            {it.label}:{mark}
          </span>
        );
      })}
    </div>
  );
}

export function DetectionPage() {
  const { scope, timeRange, showNotice } = useConsoleContext();
  const navigate = useNavigate();
  const uid = useId();

  const [activeTab, setActiveTab] = useState<DetectionTab>("signals");
  const tabRefs = useRef<Record<DetectionTab, HTMLButtonElement | null>>({
    signals: null,
    groups: null,
    matches: null,
    rules: null,
    sandbox: null,
  });

  // Filters
  const [sigStatus, setSigStatus] = useState<SignalStatus | "">("");
  const [sigSeverity, setSigSeverity] = useState<RuleSeverity | "">("");
  const [matchType, setMatchType] = useState<DetectionType | "">("");
  const [matchRuleFilter, setMatchRuleFilter] = useState("");
  const [ruleSource, setRuleSource] = useState<RuleSource | "">("");
  const [ruleStatus, setRuleStatus] = useState<RuleStatus | "">("");
  const [ruleTag, setRuleTag] = useState("");
  const [ruleQuery, setRuleQuery] = useState("");

  // Selections
  const [selectedSignalId, setSelectedSignalId] = useState<string | null>(null);
  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null);
  const [selectedMatchId, setSelectedMatchId] = useState<string | null>(null);
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null);

  // Sandbox & Import state
  const [sandboxYaml, setSandboxYaml] = useState(SAMPLE_SIGMA_YAML);
  const [sandboxPresetRuleId, setSandboxPresetRuleId] = useState("");
  const [validationPreview, setValidationPreview] = useState<DetectionRuleDetailDto | null>(null);
  const [testResult, setTestResult] = useState<RuleTestResponseDto | null>(null);
  const [isValidating, setIsValidating] = useState(false);

  // Queries
  const metricsQ = useMetricsQuery(scope);
  const rulesQ = useDetectionRulesQuery(scope, {
    source: ruleSource || undefined,
    status: ruleStatus || undefined,
    attackTag: ruleTag.trim() || undefined,
    q: ruleQuery.trim() || undefined,
  });
  const allRulesQ = useDetectionRulesQuery(scope);
  const ruleDetailQ = useDetectionRuleDetailQuery(scope, selectedRuleId);

  const signalsReq = useMemo(
    () => ({
      time_range: timeRange,
      status: sigStatus || null,
      severity: sigSeverity || null,
      limit: 200,
    }),
    [timeRange, sigStatus, sigSeverity],
  );
  const signalsQ = useSignalsQuery(scope, signalsReq);
  const activeSignal = useMemo(() => {
    const list = signalsQ.data?.items ?? [];
    return list.find((s) => s.signal_id === selectedSignalId) ?? list[0] ?? null;
  }, [signalsQ.data, selectedSignalId]);
  const sigMatchesQ = useSignalMatchesQuery(scope, activeSignal?.signal_id ?? null);
  const sigEvidenceQ = useSignalEvidenceQuery(scope, activeSignal?.signal_id ?? null);

  const groupsReq = useMemo(() => ({ time_range: timeRange, limit: 100 }), [timeRange]);
  const groupsQ = useCandidateGroupsQuery(scope, groupsReq);
  const activeGroup = useMemo(() => {
    const list = groupsQ.data?.items ?? [];
    return list.find((g) => g.group_id === selectedGroupId) ?? list[0] ?? null;
  }, [groupsQ.data, selectedGroupId]);
  const groupMembersQ = useCandidateGroupMembersQuery(scope, activeGroup?.group_id ?? null);

  const matchesReq = useMemo(
    () => ({
      time_range: timeRange,
      detection_type: matchType || null,
      rule_id: matchRuleFilter.trim() || null,
      limit: 200,
    }),
    [timeRange, matchType, matchRuleFilter],
  );
  const matchesQ = useRuleMatchesQuery(scope, matchesReq);
  const activeMatch = useMemo(() => {
    const list = matchesQ.data?.items ?? [];
    return list.find((m) => m.match_id === selectedMatchId) ?? list[0] ?? null;
  }, [matchesQ.data, selectedMatchId]);

  // Mutations
  const execBatchM = useExecuteBatchMutation(scope);
  const toggleRuleM = useToggleRuleMutation(scope);
  const importRuleM = useImportRuleMutation(scope);
  const testRuleM = useTestRuleMutation(scope);
  const updateSigStatusM = useUpdateSignalStatusMutation(scope);

  function selectTab(next: DetectionTab, focusTab = false) {
    setActiveTab(next);
    const btn = tabRefs.current[next];
    if (btn) {
      btn.scrollIntoView({ block: "nearest", inline: "nearest" });
      if (focusTab) btn.focus();
    }
  }

  function handleTabKeyDown(e: KeyboardEvent<HTMLDivElement>) {
    const idx = TABS.findIndex((t) => t.id === activeTab);
    if (idx < 0) return;
    let nextIdx = -1;
    if (e.key === "ArrowRight") nextIdx = (idx + 1) % TABS.length;
    else if (e.key === "ArrowLeft") nextIdx = (idx - 1 + TABS.length) % TABS.length;
    else if (e.key === "Home") nextIdx = 0;
    else if (e.key === "End") nextIdx = TABS.length - 1;
    if (nextIdx >= 0) {
      e.preventDefault();
      selectTab(TABS[nextIdx]!.id, true);
    }
  }

  async function runBatchDetection() {
    try {
      const ex = await execBatchM.mutateAsync({ timeRange });
      showNotice(
        ex.failures.length ? "info" : "success",
        `批量检测完成 (${ex.duration_ms.toFixed(1)} ms)：评估 ${ex.rules_evaluated} 条规则，新增命中 ${ex.matches_created} 条（幂等去重 ${ex.matches_deduplicated}），新增 Signal ${ex.signals_created} 个，候选组 ${ex.candidate_groups_created} 个。`,
      );
    } catch (err) {
      showNotice("error", err instanceof Error ? err.message : "执行批量检测失败");
    }
  }

  async function handleToggleRule(rule: DetectionRuleDto) {
    const enable = rule.status !== "ENABLED";
    try {
      await toggleRuleM.mutateAsync({ ruleId: rule.rule_id, enable });
      showNotice("success", `规则 ${rule.rule_name} 已${enable ? "启用" : "禁用"}`);
    } catch (err) {
      showNotice("error", err instanceof Error ? err.message : "切换规则状态失败");
    }
  }

  async function handleValidateOnly() {
    setIsValidating(true);
    setTestResult(null);
    try {
      const res = await detectionApi.validateRule(scope, sandboxYaml);
      setValidationPreview(res);
      showNotice(
        res.rule.compatibility.compile_success ? "success" : "info",
        res.rule.compatibility.compile_success
          ? "规则语法、OCSF 映射与参数化 SQL 编译校验通过"
          : `规则兼容性受限：${res.rule.compatibility.unsupported_reasons.join("; ")}`,
      );
    } catch (err) {
      showNotice("error", err instanceof Error ? err.message : "规则校验失败");
    } finally {
      setIsValidating(false);
    }
  }

  async function handleSandboxSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setValidationPreview(null);
    try {
      const res = await testRuleM.mutateAsync({
        time_range: timeRange,
        raw_yaml: sandboxYaml,
        max_matches: 100,
      });
      setTestResult(res);
      showNotice(
        res.failure_reason ? "info" : "success",
        res.failure_reason
          ? `沙盒测试返回受限原因：${res.failure_reason}`
          : `沙盒执行成功 (${res.duration_ms.toFixed(1)} ms)，命中 ${res.matches.length} 条记录`,
      );
    } catch (err) {
      showNotice("error", err instanceof Error ? err.message : "规则沙盒测试失败");
    }
  }

  async function handleImportFromSandbox() {
    try {
      const imported = await importRuleM.mutateAsync({ rawYaml: sandboxYaml });
      setSelectedRuleId(imported.rule.rule_id);
      showNotice("success", `已导入规则 ${imported.rule.rule_name} (${imported.rule.status})`);
    } catch (err) {
      showNotice("error", err instanceof Error ? err.message : "导入规则失败");
    }
  }

  const signalColumns = useMemo<ColumnDef<SignalDto, unknown>[]>(
    () => [
      {
        accessorKey: "severity",
        header: "严重程度",
        cell: ({ getValue }) => <RuleSeverityPill severity={getValue() as RuleSeverity} />,
      },
      {
        accessorKey: "title",
        header: "可疑线索 (Signal)",
        cell: ({ row }) => (
          <div>
            <div className="font-semibold text-xs">{row.original.title}</div>
            <div className="font-mono-code text-[11px] text-[var(--pl-text-muted)]">
              {row.original.signal_type}
            </div>
          </div>
        ),
      },
      {
        accessorKey: "status",
        header: "处理进度",
        cell: ({ getValue }) => <SignalStatusPill status={getValue() as SignalStatus} />,
      },
      {
        accessorKey: "occurrence_count",
        header: "关联命中",
        cell: ({ row }) => (
          <span className="font-mono-code text-xs">
            {row.original.occurrence_count} ({row.original.event_ids.length} events)
          </span>
        ),
      },
      {
        accessorKey: "last_seen_at",
        header: "最后观测 (UTC)",
        cell: ({ getValue }) => (
          <span className="font-mono-code text-[11px]">{String(getValue())}</span>
        ),
      },
    ],
    [],
  );

  const groupColumns = useMemo<ColumnDef<CandidateGroupDto, unknown>[]>(
    () => [
      {
        accessorKey: "certainty",
        header: "关联确定性",
        cell: ({ getValue }) => (
          <CertaintyPill certainty={getValue() as CandidateGroupDto["certainty"]} />
        ),
      },
      {
        accessorKey: "grouping_rule_id",
        header: "聚合依据规则",
        cell: ({ getValue }) => (
          <span className="font-mono-code text-xs font-semibold">{String(getValue())}</span>
        ),
      },
      {
        id: "members",
        header: "成员规模",
        accessorFn: (row) => row.signal_ids.length,
        cell: ({ row }) => (
          <span className="font-mono-code text-xs">
            {row.original.signal_ids.length} Signals · {row.original.rule_match_ids.length} Matches
          </span>
        ),
      },
      {
        id: "ambiguities",
        header: "未解决歧义",
        accessorFn: (row) => row.unresolved_ambiguities.length,
        cell: ({ row }) => {
          const n = row.original.unresolved_ambiguities.length;
          return (
            <span
              className={`font-mono-code text-xs ${n > 0 ? "text-amber-500 font-semibold" : "text-[var(--pl-text-muted)]"}`}
            >
              {n > 0 ? `${n} 项待核实` : "无"}
            </span>
          );
        },
      },
      {
        accessorKey: "last_seen_at",
        header: "时间窗终点",
        cell: ({ getValue }) => (
          <span className="font-mono-code text-[11px]">{String(getValue())}</span>
        ),
      },
    ],
    [],
  );

  const matchColumns = useMemo<ColumnDef<RuleMatchDto, unknown>[]>(
    () => [
      {
        accessorKey: "matched_at",
        header: "命中时间 (UTC)",
        cell: ({ getValue }) => (
          <span className="font-mono-code text-[11px]">{String(getValue())}</span>
        ),
      },
      {
        accessorKey: "severity",
        header: "等级",
        cell: ({ getValue }) => <RuleSeverityPill severity={getValue() as RuleSeverity} />,
      },
      {
        accessorKey: "detection_type",
        header: "类型",
        cell: ({ getValue }) => (
          <span className="font-mono-code text-[11px] px-1.5 py-0.5 rounded border border-[var(--pl-border)] bg-[var(--pl-surface-alt)]">
            {String(getValue())}
          </span>
        ),
      },
      {
        accessorKey: "rule_name",
        header: "触发规则",
        cell: ({ row }) => (
          <div>
            <div className="font-semibold text-xs">{row.original.rule_name}</div>
            <div className="font-mono-code text-[10px] text-[var(--pl-text-muted)]">
              {row.original.rule_id} · v{row.original.rule_version}
            </div>
          </div>
        ),
      },
      {
        id: "fields",
        header: "匹配字段",
        accessorFn: (row) => row.matched_fields.join(", "),
        cell: ({ row }) => (
          <span className="font-mono-code text-[11px] text-[var(--pl-text-muted)]">
            {row.original.matched_fields.join(", ")}
          </span>
        ),
      },
    ],
    [],
  );

  const ruleColumns = useMemo<ColumnDef<DetectionRuleDto, unknown>[]>(
    () => [
      {
        accessorKey: "source",
        header: "来源",
        cell: ({ getValue }) => (
          <span className="font-mono-code text-[11px] px-1.5 py-0.5 rounded border border-[var(--pl-border)] bg-[var(--pl-surface-alt)]">
            {String(getValue())}
          </span>
        ),
      },
      {
        accessorKey: "rule_name",
        header: "规则名称 / ATT&CK",
        cell: ({ row }) => (
          <div className="space-y-1">
            <div className="font-semibold text-xs">{row.original.rule_name}</div>
            <div className="flex flex-wrap gap-1">
              {row.original.attack_tags.slice(0, 4).map((tag) => (
                <span
                  key={tag}
                  className="font-mono-code text-[10px] px-1 py-0.2 rounded bg-[var(--pl-surface-alt)] border border-[var(--pl-border)] text-[var(--pl-text-muted)]"
                >
                  {tag}
                </span>
              ))}
            </div>
          </div>
        ),
      },
      {
        accessorKey: "severity",
        header: "严重程度",
        cell: ({ getValue }) => <RuleSeverityPill severity={getValue() as RuleSeverity} />,
      },
      {
        id: "compat",
        header: "五阶段兼容性",
        accessorFn: (row) => Number(row.compatibility.compile_success),
        cell: ({ row }) => <CompatibilityStages compat={row.original.compatibility} />,
      },
      {
        accessorKey: "status",
        header: "状态",
        cell: ({ getValue }) => <RuleStatusPill status={getValue() as RuleStatus} />,
      },
      {
        id: "actions",
        header: "操作",
        cell: ({ row }) => {
          const r = row.original;
          const supported =
            r.compatibility.parse_success &&
            r.compatibility.mapping_success &&
            r.compatibility.compile_success;
          return (
            <div className="flex flex-wrap gap-1.5" onClick={(ev) => ev.stopPropagation()}>
              <button
                type="button"
                disabled={!supported || toggleRuleM.isPending}
                onClick={() => void handleToggleRule(r)}
                aria-label={`${r.status === "ENABLED" ? "禁用" : "启用"}规则 ${r.rule_name}`}
                className="px-2 py-0.5 rounded border border-[var(--pl-border-strong)] bg-[var(--pl-surface-alt)] text-[11px] cursor-pointer disabled:opacity-40"
              >
                {r.status === "ENABLED" ? "禁用" : "启用"}
              </button>
              <button
                type="button"
                onClick={() => {
                  setSandboxYaml(r.raw_content);
                  setTestResult(null);
                  setValidationPreview(null);
                  selectTab("sandbox");
                }}
                aria-label={`在沙盒中测试规则 ${r.rule_name}`}
                className="px-2 py-0.5 rounded border border-[var(--pl-accent)] text-[var(--pl-accent)] text-[11px] cursor-pointer"
              >
                测试
              </button>
            </div>
          );
        },
      },
    ],
    [toggleRuleM.isPending],
  );

  const snap = metricsQ.data;
  const allRules = allRulesQ.data?.items ?? [];
  const supportedCount = allRules.filter((r) => r.compatibility.compile_success).length;
  const unsupportedCount = allRules.length - supportedCount;

  const activeSandboxRule = testResult?.rule ?? validationPreview?.rule ?? null;
  const activeSandboxSql = testResult?.compiled_sql ?? validationPreview?.compiled_sql ?? null;
  const activeSandboxParsed =
    testResult?.parsed_summary ?? validationPreview?.parsed_summary ?? null;
  const activeSandboxMappings =
    testResult?.field_mappings ?? validationPreview?.rule.compatibility.field_mappings ?? {};

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-base font-bold tracking-tight">
            检测与调查线索中心 (Detection & Signal Layer)
          </h1>
          <p className="text-xs text-[var(--pl-text-muted)]">
            基于 pySigma OCSF v1.4.0 参数化 SQL 与一跳确定性图关系检测，产出可追溯的 RuleMatch、Signal 与 CandidateGroup（不直接断言攻击定性）。
          </p>
        </div>

        <button
          type="button"
          disabled={execBatchM.isPending}
          onClick={() => void runBatchDetection()}
          className="px-3.5 py-2 rounded-md bg-[var(--pl-accent)] hover:opacity-90 text-white text-xs font-semibold cursor-pointer disabled:opacity-60"
        >
          {execBatchM.isPending ? "检测执行中…" : "批量执行启用规则 (Batch Run)"}
        </button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-2.5">
        <div className="pl-surface rounded-lg p-3">
          <div className="text-[11px] text-[var(--pl-text-muted)]">规则库 (支持 / 受限)</div>
          <div className="mt-1 font-mono-code text-lg font-bold">
            {supportedCount} <span className="text-xs text-amber-500">/ {unsupportedCount}</span>
          </div>
        </div>
        <div className="pl-surface rounded-lg p-3">
          <div className="text-[11px] text-[var(--pl-text-muted)]">时间窗内 Signal 线索</div>
          <div className="mt-1 font-mono-code text-lg font-bold text-blue-500">
            {signalsQ.data?.items.length ?? 0}
          </div>
        </div>
        <div className="pl-surface rounded-lg p-3">
          <div className="text-[11px] text-[var(--pl-text-muted)]">时间窗内 RuleMatch</div>
          <div className="mt-1 font-mono-code text-lg font-bold">
            {matchesQ.data?.items.length ?? 0}
          </div>
        </div>
        <div className="pl-surface rounded-lg p-3">
          <div className="text-[11px] text-[var(--pl-text-muted)]">候选关联组 (CandidateGroup)</div>
          <div className="mt-1 font-mono-code text-lg font-bold text-emerald-500">
            {groupsQ.data?.items.length ?? 0}
          </div>
        </div>
        <div className="pl-surface rounded-lg p-3">
          <div className="text-[11px] text-[var(--pl-text-muted)]">累计检测批次 / 聚合次数</div>
          <div className="mt-1 font-mono-code text-lg font-bold">
            {snap?.detection_executions_total ?? 0}{" "}
            <span className="text-xs text-[var(--pl-text-muted)]">
              / {snap?.signals_aggregated_total ?? 0}
            </span>
          </div>
        </div>
      </div>

      <div>
        <div
          role="tablist"
          aria-label="检测控制台视图"
          onKeyDown={handleTabKeyDown}
          className="pl-tablist"
        >
          {TABS.map((t) => {
            const isSelected = activeTab === t.id;
            return (
              <button
                key={t.id}
                ref={(el) => {
                  tabRefs.current[t.id] = el;
                }}
                id={`${uid}-tab-${t.id}`}
                type="button"
                role="tab"
                aria-selected={isSelected}
                tabIndex={isSelected ? 0 : -1}
                onClick={() => selectTab(t.id)}
                className="pl-tab"
              >
                {t.label}
              </button>
            );
          })}
        </div>

        {/* Tab 1: Signals */}
        <div
          role="tabpanel"
          aria-labelledby={`${uid}-tab-signals`}
          hidden={activeTab !== "signals"}
        >
          <div className="pl-surface rounded-b-lg p-3.5 space-y-3 border-t-0">
            <search>
              <div className="flex flex-wrap items-end gap-3">
                <div className="flex flex-col gap-1">
                  <label
                    htmlFor={`${uid}-sig-status`}
                    className="text-[11px] text-[var(--pl-text-muted)]"
                  >
                    处理状态
                  </label>
                  <select
                    id={`${uid}-sig-status`}
                    name="signal_status"
                    value={sigStatus}
                    onChange={(e) => setSigStatus(e.target.value as SignalStatus | "")}
                    className="pl-input w-40"
                  >
                    <option value="">全部状态</option>
                    {SIGNAL_STATUSES.map((st) => (
                      <option key={st} value={st}>
                        {st}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="flex flex-col gap-1">
                  <label
                    htmlFor={`${uid}-sig-sev`}
                    className="text-[11px] text-[var(--pl-text-muted)]"
                  >
                    严重程度
                  </label>
                  <select
                    id={`${uid}-sig-sev`}
                    name="signal_severity"
                    value={sigSeverity}
                    onChange={(e) => setSigSeverity(e.target.value as RuleSeverity | "")}
                    className="pl-input w-40"
                  >
                    <option value="">全部等级</option>
                    {SEVERITIES.map((sv) => (
                      <option key={sv} value={sv}>
                        {sv}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            </search>

            <div className="grid grid-cols-1 xl:grid-cols-12 gap-3.5">
              <div className="xl:col-span-7">
                <DataTable
                  caption="可疑行为调查线索列表"
                  columns={signalColumns}
                  data={signalsQ.data?.items ?? []}
                  getRowId={(r) => r.signal_id}
                  selectedRowId={activeSignal?.signal_id ?? null}
                  onRowClick={(r) => setSelectedSignalId(r.signal_id)}
                  emptyMessage="当前时间窗暂无 Signal，可先导入内置标准样本并点击右上角「批量执行启用规则」。"
                />
              </div>

              <div className="xl:col-span-5 pl-surface-alt rounded-lg p-3.5 space-y-3">
                {activeSignal ? (
                  <>
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <h2 className="text-sm font-bold">{activeSignal.title}</h2>
                        <div className="font-mono-code text-[11px] text-[var(--pl-text-muted)]">
                          ID: {activeSignal.signal_id}
                        </div>
                      </div>
                      <RuleSeverityPill severity={activeSignal.severity} />
                    </div>

                    <div className="rounded border border-amber-500/40 bg-amber-500/10 px-2.5 py-1.5 text-[11px] text-amber-500">
                      边界说明：Signal 状态仅记录线索跟进进度，不代表确认攻击结论；底层 RuleMatch 永久保留。
                    </div>

                    <div className="flex flex-wrap items-end justify-between gap-2">
                      <div className="flex flex-col gap-1">
                        <label
                          htmlFor={`${uid}-sig-lifecycle`}
                          className="text-[11px] text-[var(--pl-text-muted)]"
                        >
                          更新线索生命周期状态
                        </label>
                        <select
                          id={`${uid}-sig-lifecycle`}
                          name="lifecycle_status"
                          value={activeSignal.status}
                          disabled={updateSigStatusM.isPending}
                          onChange={(e) =>
                            void updateSigStatusM.mutateAsync({
                              signalId: activeSignal.signal_id,
                              status: e.target.value as SignalStatus,
                            })
                          }
                          className="pl-input w-44"
                        >
                          {SIGNAL_STATUSES.map((st) => (
                            <option key={st} value={st}>
                              {st}
                            </option>
                          ))}
                        </select>
                      </div>

                      {activeSignal.primary_entity_id && (
                        <div className="flex flex-wrap gap-1.5">
                          <button
                            type="button"
                            onClick={() =>
                              navigate(
                                `/entities?entityId=${encodeURIComponent(activeSignal.primary_entity_id!)}`,
                              )
                            }
                            className="px-2.5 py-1.5 rounded border border-[var(--pl-border-strong)] bg-[var(--pl-surface)] hover:border-[var(--pl-accent)] text-xs cursor-pointer"
                          >
                            查看主实体详情
                          </button>
                          <button
                            type="button"
                            onClick={() =>
                              navigate(
                                `/graph?seed=${encodeURIComponent(activeSignal.primary_entity_id!)}`,
                              )
                            }
                            className="px-2.5 py-1.5 rounded bg-[var(--pl-accent)] text-white text-xs font-medium cursor-pointer"
                          >
                            跳转实体关系图谱
                          </button>
                        </div>
                      )}
                    </div>

                    <div className="text-xs space-y-1">
                      <div>
                        <span className="text-[var(--pl-text-muted)]">时间范围：</span>
                        <span className="font-mono-code">
                          {activeSignal.first_seen_at} ~ {activeSignal.last_seen_at}
                        </span>
                      </div>
                      <div>
                        <span className="text-[var(--pl-text-muted)]">数据来源：</span>
                        <span className="font-mono-code">{activeSignal.source_ids.join(", ")}</span>
                      </div>
                      <div>
                        <span className="text-[var(--pl-text-muted)]">关联 RuleMatch：</span>
                        <span className="font-mono-code">
                          {sigMatchesQ.data?.length ?? activeSignal.rule_match_ids.length} 条
                        </span>
                      </div>
                    </div>

                    <div className="space-y-1.5">
                      <h3 className="text-xs font-semibold">
                        支撑 OCSF 事件与原始日志证据 ({sigEvidenceQ.data?.length ?? 0})
                      </h3>
                      <div className="max-h-72 overflow-y-auto space-y-2">
                        {(sigEvidenceQ.data ?? []).map((ev) => (
                          <div
                            key={ev.event_id}
                            className="rounded border border-[var(--pl-border)] bg-[var(--pl-surface)] p-2.5 space-y-1.5 text-xs"
                          >
                            <div className="flex flex-wrap items-center justify-between gap-1 font-mono-code text-[11px]">
                              <span>
                                class_uid={ev.ocsf_class_uid} · src={ev.source_id}
                              </span>
                              <span className="text-[var(--pl-text-muted)]">{ev.event_time}</span>
                            </div>
                            <div className="font-mono-code text-[10px] text-[var(--pl-text-muted)]">
                              event_id={ev.event_id} · raw_event_id={ev.raw_event_id}
                            </div>
                            <pre className="pl-code-box rounded p-2 text-[11px] overflow-x-auto whitespace-pre-wrap break-all">
                              {ev.raw_payload}
                            </pre>
                          </div>
                        ))}
                      </div>
                    </div>
                  </>
                ) : (
                  <div className="text-xs text-[var(--pl-text-muted)] py-8 text-center">
                    选择左侧一条 Signal 查看关联规则命中与原始证据链。
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Tab 2: CandidateGroups */}
        <div
          role="tabpanel"
          aria-labelledby={`${uid}-tab-groups`}
          hidden={activeTab !== "groups"}
        >
          <div className="pl-surface rounded-b-lg p-3.5 space-y-3 border-t-0">
            <div className="grid grid-cols-1 xl:grid-cols-12 gap-3.5">
              <div className="xl:col-span-7">
                <DataTable
                  caption="程序生成的候选线索关联组"
                  columns={groupColumns}
                  data={groupsQ.data?.items ?? []}
                  getRowId={(g) => g.group_id}
                  selectedRowId={activeGroup?.group_id ?? null}
                  onRowClick={(g) => setSelectedGroupId(g.group_id)}
                  emptyMessage="当前时间窗暂无多线索确定性交集形成的 CandidateGroup。"
                />
              </div>

              <div className="xl:col-span-5 pl-surface-alt rounded-lg p-3.5 space-y-3">
                {activeGroup ? (
                  <>
                    <div className="flex items-center justify-between gap-2">
                      <h2 className="text-sm font-bold font-mono-code">
                        {activeGroup.grouping_rule_id}
                      </h2>
                      <CertaintyPill certainty={activeGroup.certainty} />
                    </div>

                    <div className="text-xs text-[var(--pl-text-muted)]">
                      时间跨度：
                      <span className="font-mono-code text-[var(--pl-text)]">
                        {" "}
                        {activeGroup.first_seen_at} ~ {activeGroup.last_seen_at}
                      </span>
                    </div>

                    {activeGroup.shared_entity_ids.length > 0 && (
                      <div className="space-y-1">
                        <h3 className="text-xs font-semibold">共享锚点实体</h3>
                        <div className="flex flex-wrap gap-1.5">
                          {activeGroup.shared_entity_ids.map((eid) => (
                            <button
                              key={eid}
                              type="button"
                              onClick={() => navigate(`/graph?seed=${encodeURIComponent(eid)}`)}
                              className="px-2 py-1 rounded border border-[var(--pl-accent)] text-[var(--pl-accent)] font-mono-code text-[11px] cursor-pointer"
                            >
                              图谱展开 {eid.slice(0, 8)}…
                            </button>
                          ))}
                        </div>
                      </div>
                    )}

                    <div className="space-y-1">
                      <h3 className="text-xs font-semibold">
                        组内 Signal 成员 ({groupMembersQ.data?.signals.length ?? 0})
                      </h3>
                      <ul className="space-y-1 text-xs">
                        {(groupMembersQ.data?.signals ?? []).map((s) => (
                          <li
                            key={s.signal_id}
                            className="flex items-center justify-between gap-2 rounded border border-[var(--pl-border)] bg-[var(--pl-surface)] px-2.5 py-1.5"
                          >
                            <span className="font-medium">{s.title}</span>
                            <RuleSeverityPill severity={s.severity} />
                          </li>
                        ))}
                      </ul>
                    </div>

                    <div className="space-y-1">
                      <h3 className="text-xs font-semibold">未解决的关联歧义</h3>
                      {activeGroup.unresolved_ambiguities.length > 0 ? (
                        <ul className="space-y-1 text-[11px] text-amber-500">
                          {activeGroup.unresolved_ambiguities.map((amb) => (
                            <li
                              key={amb}
                              className="rounded border border-amber-500/40 bg-amber-500/10 px-2 py-1 font-mono-code"
                            >
                              {amb}
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p className="text-xs text-[var(--pl-text-muted)]">
                          当前组内未发现 PROVISIONAL 实体或未验证的 CANDIDATE 候选边歧义。
                        </p>
                      )}
                    </div>

                    <div className="space-y-1">
                      <h3 className="text-xs font-semibold">确定性聚合依据 (grouping_basis)</h3>
                      <JsonViewer value={activeGroup.grouping_basis} maxHeightClass="max-h-48" />
                    </div>
                  </>
                ) : (
                  <div className="text-xs text-[var(--pl-text-muted)] py-8 text-center">
                    选择左侧一个 CandidateGroup 查看组内成员、聚合依据与歧义提示。
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Tab 3: RuleMatches */}
        <div
          role="tabpanel"
          aria-labelledby={`${uid}-tab-matches`}
          hidden={activeTab !== "matches"}
        >
          <div className="pl-surface rounded-b-lg p-3.5 space-y-3 border-t-0">
            <search>
              <div className="flex flex-wrap items-end gap-3">
                <div className="flex flex-col gap-1">
                  <label
                    htmlFor={`${uid}-match-type`}
                    className="text-[11px] text-[var(--pl-text-muted)]"
                  >
                    检测类型
                  </label>
                  <select
                    id={`${uid}-match-type`}
                    name="detection_type"
                    value={matchType}
                    onChange={(e) => setMatchType(e.target.value as DetectionType | "")}
                    className="pl-input w-40"
                  >
                    <option value="">EVENT + RELATION</option>
                    <option value="EVENT">EVENT (单事件)</option>
                    <option value="RELATION">RELATION (一跳关系)</option>
                  </select>
                </div>

                <div className="flex flex-col gap-1">
                  <label
                    htmlFor={`${uid}-match-rule`}
                    className="text-[11px] text-[var(--pl-text-muted)]"
                  >
                    按 Rule ID 精确筛选
                  </label>
                  <input
                    id={`${uid}-match-rule`}
                    name="rule_id"
                    type="search"
                    value={matchRuleFilter}
                    onChange={(e) => setMatchRuleFilter(e.target.value)}
                    autoCorrect="off"
                    autoCapitalize="none"
                    spellCheck={false}
                    placeholder="输入 rule_id"
                    className="pl-input w-64 font-mono-code"
                  />
                </div>
              </div>
            </search>

            <div className="grid grid-cols-1 xl:grid-cols-12 gap-3.5">
              <div className="xl:col-span-7">
                <DataTable
                  caption="不可变规则命中记录表"
                  columns={matchColumns}
                  data={matchesQ.data?.items ?? []}
                  getRowId={(m) => m.match_id}
                  selectedRowId={activeMatch?.match_id ?? null}
                  onRowClick={(m) => setSelectedMatchId(m.match_id)}
                  emptyMessage="当前筛选条件下暂无 RuleMatch 记录。"
                />
              </div>

              <div className="xl:col-span-5 pl-surface-alt rounded-lg p-3.5 space-y-3">
                {activeMatch ? (
                  <>
                    <div>
                      <h2 className="text-sm font-bold">{activeMatch.rule_name}</h2>
                      <div className="font-mono-code text-[11px] text-[var(--pl-text-muted)]">
                        match_id: {activeMatch.match_id}
                      </div>
                    </div>

                    {activeMatch.primary_entity_id && (
                      <div className="flex flex-wrap gap-1.5">
                        <button
                          type="button"
                          onClick={() =>
                            navigate(
                              `/entities?entityId=${encodeURIComponent(activeMatch.primary_entity_id!)}`,
                            )
                          }
                          className="px-2.5 py-1 rounded border border-[var(--pl-border-strong)] bg-[var(--pl-surface)] text-xs cursor-pointer"
                        >
                          主实体: {activeMatch.primary_entity_id.slice(0, 8)}…
                        </button>
                        <button
                          type="button"
                          onClick={() =>
                            navigate(
                              `/graph?seed=${encodeURIComponent(activeMatch.primary_entity_id!)}`,
                            )
                          }
                          className="px-2.5 py-1 rounded border border-[var(--pl-accent)] text-[var(--pl-accent)] text-xs cursor-pointer"
                        >
                          溯源图谱定位
                        </button>
                      </div>
                    )}

                    <div className="space-y-1">
                      <h3 className="text-xs font-semibold">命中字段与实际值</h3>
                      <JsonViewer value={activeMatch.matched_values} maxHeightClass="max-h-48" />
                    </div>

                    <div className="space-y-1">
                      <h3 className="text-xs font-semibold">证据链引用 (evidence_references)</h3>
                      <JsonViewer
                        value={activeMatch.evidence_references}
                        maxHeightClass="max-h-48"
                      />
                    </div>
                  </>
                ) : (
                  <div className="text-xs text-[var(--pl-text-muted)] py-8 text-center">
                    选择左侧一条 RuleMatch 查看命中字段与原始证据引用。
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Tab 4: Rule Management */}
        <div role="tabpanel" aria-labelledby={`${uid}-tab-rules`} hidden={activeTab !== "rules"}>
          <div className="pl-surface rounded-b-lg p-3.5 space-y-3 border-t-0">
            <search>
              <div className="flex flex-wrap items-end gap-3">
                <div className="flex flex-col gap-1">
                  <label
                    htmlFor={`${uid}-rule-src`}
                    className="text-[11px] text-[var(--pl-text-muted)]"
                  >
                    规则来源
                  </label>
                  <select
                    id={`${uid}-rule-src`}
                    name="source"
                    value={ruleSource}
                    onChange={(e) => setRuleSource(e.target.value as RuleSource | "")}
                    className="pl-input w-36"
                  >
                    <option value="">全部 (Sigma + Custom)</option>
                    <option value="SIGMA">SIGMA</option>
                    <option value="CUSTOM">CUSTOM</option>
                  </select>
                </div>

                <div className="flex flex-col gap-1">
                  <label
                    htmlFor={`${uid}-rule-st`}
                    className="text-[11px] text-[var(--pl-text-muted)]"
                  >
                    规则状态
                  </label>
                  <select
                    id={`${uid}-rule-st`}
                    name="status"
                    value={ruleStatus}
                    onChange={(e) => setRuleStatus(e.target.value as RuleStatus | "")}
                    className="pl-input w-36"
                  >
                    <option value="">全部状态</option>
                    <option value="ENABLED">ENABLED</option>
                    <option value="DISABLED">DISABLED</option>
                    <option value="UNSUPPORTED">UNSUPPORTED</option>
                    <option value="ERROR">ERROR</option>
                  </select>
                </div>

                <div className="flex flex-col gap-1">
                  <label
                    htmlFor={`${uid}-rule-tag`}
                    className="text-[11px] text-[var(--pl-text-muted)]"
                  >
                    ATT&CK 标签筛选
                  </label>
                  <input
                    id={`${uid}-rule-tag`}
                    name="attack_tag"
                    type="search"
                    value={ruleTag}
                    onChange={(e) => setRuleTag(e.target.value)}
                    autoCorrect="off"
                    autoCapitalize="none"
                    spellCheck={false}
                    placeholder="如 t1059 或 credential_access"
                    className="pl-input w-48 font-mono-code"
                  />
                </div>

                <div className="flex flex-col gap-1">
                  <label
                    htmlFor={`${uid}-rule-q`}
                    className="text-[11px] text-[var(--pl-text-muted)]"
                  >
                    名称或描述搜索
                  </label>
                  <input
                    id={`${uid}-rule-q`}
                    name="q"
                    type="search"
                    value={ruleQuery}
                    onChange={(e) => setRuleQuery(e.target.value)}
                    placeholder="PowerShell / LSASS"
                    className="pl-input w-48"
                  />
                </div>
              </div>
            </search>

            <div className="grid grid-cols-1 xl:grid-cols-12 gap-3.5">
              <div className="xl:col-span-7">
                <DataTable
                  caption="检测规则与兼容性注册表"
                  columns={ruleColumns}
                  data={rulesQ.data?.items ?? []}
                  getRowId={(r) => r.rule_id}
                  selectedRowId={selectedRuleId}
                  onRowClick={(r) => setSelectedRuleId(r.rule_id)}
                  emptyMessage="没有匹配的检测规则。"
                />
              </div>

              <div className="xl:col-span-5 pl-surface-alt rounded-lg p-3.5 space-y-3">
                {ruleDetailQ.data ? (
                  <>
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <h2 className="text-sm font-bold">{ruleDetailQ.data.rule.rule_name}</h2>
                        <div className="font-mono-code text-[11px] text-[var(--pl-text-muted)]">
                          {ruleDetailQ.data.rule.rule_id} · v{ruleDetailQ.data.rule.version}
                        </div>
                      </div>
                      <RuleStatusPill status={ruleDetailQ.data.rule.status} />
                    </div>

                    <p className="text-xs text-[var(--pl-text-muted)]">
                      {ruleDetailQ.data.rule.description}
                    </p>

                    <div className="text-[11px] font-mono-code text-[var(--pl-text-muted)]">
                      来源路径: {ruleDetailQ.data.rule.source_reference}
                    </div>

                    <CompatibilityStages compat={ruleDetailQ.data.rule.compatibility} />

                    {ruleDetailQ.data.rule.compatibility.unsupported_reasons.length > 0 && (
                      <div className="rounded border border-red-500/50 bg-red-500/10 p-2.5 text-xs text-red-400 space-y-1">
                        <div className="font-semibold">不兼容 / 拒绝原因：</div>
                        <ul className="list-disc pl-4 font-mono-code text-[11px]">
                          {ruleDetailQ.data.rule.compatibility.unsupported_reasons.map((rsn) => (
                            <li key={rsn}>{rsn}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {Object.keys(ruleDetailQ.data.rule.compatibility.field_mappings).length > 0 && (
                      <div className="space-y-1">
                        <h3 className="text-xs font-semibold">OCSF v1.4.0 字段映射</h3>
                        <JsonViewer
                          value={ruleDetailQ.data.rule.compatibility.field_mappings}
                          maxHeightClass="max-h-40"
                        />
                      </div>
                    )}

                    {ruleDetailQ.data.compiled_sql && (
                      <div className="space-y-1">
                        <h3 className="text-xs font-semibold">参数化 PostgreSQL 查询预览</h3>
                        <pre className="pl-code-box rounded p-2.5 text-[11px] overflow-x-auto whitespace-pre-wrap">
                          {ruleDetailQ.data.compiled_sql}
                        </pre>
                      </div>
                    )}

                    <div className="space-y-1">
                      <h3 className="text-xs font-semibold">原始规则定义 (YAML)</h3>
                      <pre className="pl-code-box rounded p-2.5 text-[11px] max-h-56 overflow-auto whitespace-pre">
                        {ruleDetailQ.data.rule.raw_content}
                      </pre>
                    </div>
                  </>
                ) : (
                  <div className="text-xs text-[var(--pl-text-muted)] py-8 text-center">
                    点击左侧任意规则查看原始 Sigma / Custom YAML、OCSF 映射与参数化 SQL。
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Tab 5: Rule Test Sandbox */}
        <div
          role="tabpanel"
          aria-labelledby={`${uid}-tab-sandbox`}
          hidden={activeTab !== "sandbox"}
        >
          <div className="pl-surface rounded-b-lg p-3.5 space-y-3 border-t-0">
            <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
              <form
                id={`${uid}-sandbox-form`}
                aria-labelledby={`${uid}-sandbox-heading`}
                method="POST"
                action="/api/v1/detection/rules/test"
                onSubmit={(e) => void handleSandboxSubmit(e)}
                className="xl:col-span-6 space-y-3"
              >
                <div className="flex flex-wrap items-end justify-between gap-2">
                  <h2 id={`${uid}-sandbox-heading`} className="text-sm font-bold">
                    Sigma / Custom 结构化规则沙盒
                  </h2>
                  <div className="flex flex-col gap-1">
                    <label
                      htmlFor={`${uid}-sandbox-preset`}
                      className="text-[11px] text-[var(--pl-text-muted)]"
                    >
                      从现有规则载入模板
                    </label>
                    <select
                      id={`${uid}-sandbox-preset`}
                      name="preset_rule_id"
                      value={sandboxPresetRuleId}
                      onChange={(e) => {
                        const rid = e.target.value;
                        setSandboxPresetRuleId(rid);
                        const found = allRules.find((r) => r.rule_id === rid);
                        if (found) {
                          setSandboxYaml(found.raw_content);
                          setTestResult(null);
                          setValidationPreview(null);
                        }
                      }}
                      className="pl-input w-64"
                    >
                      <option value="">-- 选择内置规则载入编辑器 --</option>
                      {allRules.map((r) => (
                        <option key={r.rule_id} value={r.rule_id}>
                          [{r.source}] {r.rule_name}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>

                <div className="flex flex-col gap-1">
                  <label
                    htmlFor={`${uid}-sandbox-yaml`}
                    className="text-xs font-medium text-[var(--pl-text)]"
                  >
                    规则 YAML 内容（禁止任意 SQL 或 Python 脚本）
                  </label>
                  <textarea
                    id={`${uid}-sandbox-yaml`}
                    name="raw_yaml"
                    rows={18}
                    required
                    value={sandboxYaml}
                    onChange={(e) => setSandboxYaml(e.target.value)}
                    autoCorrect="off"
                    autoCapitalize="none"
                    spellCheck={false}
                    className="pl-input w-full font-mono-code text-xs leading-relaxed"
                  />
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="submit"
                    disabled={testRuleM.isPending}
                    className="px-3.5 py-1.5 rounded-md bg-[var(--pl-accent)] text-white text-xs font-semibold cursor-pointer disabled:opacity-60"
                  >
                    {testRuleM.isPending ? "执行沙盒匹配中…" : "编译并对当前时间窗数据测试"}
                  </button>
                  <button
                    type="button"
                    disabled={isValidating}
                    onClick={() => void handleValidateOnly()}
                    className="px-3 py-1.5 rounded-md border border-[var(--pl-border-strong)] bg-[var(--pl-surface-alt)] text-xs cursor-pointer disabled:opacity-60"
                  >
                    {isValidating ? "校验中…" : "仅校验编译与兼容性"}
                  </button>
                  <button
                    type="button"
                    disabled={importRuleM.isPending}
                    onClick={() => void handleImportFromSandbox()}
                    className="px-3 py-1.5 rounded-md border border-emerald-500/60 text-emerald-500 text-xs font-medium cursor-pointer disabled:opacity-60"
                  >
                    {importRuleM.isPending ? "保存中…" : "导入保存到规则库"}
                  </button>
                </div>
              </form>

              <div className="xl:col-span-6 pl-surface-alt rounded-lg p-3.5 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h2 className="text-sm font-bold">编译诊断与测试输出</h2>
                  {testResult && (
                    <span className="font-mono-code text-xs text-[var(--pl-text-muted)]">
                      耗时: {testResult.duration_ms.toFixed(2)} ms · 命中:{" "}
                      {testResult.matches.length}
                    </span>
                  )}
                </div>

                {activeSandboxRule ? (
                  <>
                    <CompatibilityStages compat={activeSandboxRule.compatibility} />

                    {(testResult?.failure_reason ||
                      activeSandboxRule.compatibility.unsupported_reasons.length > 0) && (
                      <div
                        role="alert"
                        className="rounded border border-red-500/50 bg-red-500/10 p-2.5 text-xs text-red-400 space-y-1"
                      >
                        <div className="font-semibold">执行 / 兼容性阻断原因：</div>
                        <div className="font-mono-code text-[11px]">
                          {testResult?.failure_reason ||
                            activeSandboxRule.compatibility.unsupported_reasons.join("; ")}
                        </div>
                      </div>
                    )}

                    {activeSandboxParsed && (
                      <div className="space-y-1">
                        <h3 className="text-xs font-semibold">1. pySigma / 结构化语法解析结果</h3>
                        <JsonViewer value={activeSandboxParsed} maxHeightClass="max-h-36" />
                      </div>
                    )}

                    <div className="space-y-1">
                      <h3 className="text-xs font-semibold">2. OCSF v1.4.0 字段映射</h3>
                      <JsonViewer value={activeSandboxMappings} maxHeightClass="max-h-36" />
                    </div>

                    {activeSandboxSql && (
                      <div className="space-y-1">
                        <h3 className="text-xs font-semibold">3. 参数化 PostgreSQL SQL 编译结果</h3>
                        <pre className="pl-code-box rounded p-2.5 text-[11px] overflow-x-auto whitespace-pre-wrap">
                          {activeSandboxSql}
                        </pre>
                      </div>
                    )}

                    {testResult && (
                      <div className="space-y-1">
                        <h3 className="text-xs font-semibold">
                          4. 沙盒匹配结果 ({testResult.matches.length})
                        </h3>
                        <JsonViewer value={testResult.matches} maxHeightClass="max-h-56" />
                      </div>
                    )}
                  </>
                ) : (
                  <div className="text-xs text-[var(--pl-text-muted)] py-12 text-center">
                    点击左侧「编译并对当前时间窗数据测试」或「仅校验编译与兼容性」查看解析树、OCSF 字段映射、参数化 SQL 与命中详情。
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
