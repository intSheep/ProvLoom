import type {
  BatchStatus,
  Certainty,
  EntityType,
  NormalizationStatus,
  PipelineStage,
  ResolutionState,
  RuleSeverity,
  RuleStatus,
  SignalStatus,
} from "../../api/types";

const ENTITY_TYPE_TONE: Record<EntityType, string> = {
  HOST: "border-blue-500/50 text-blue-500 bg-blue-500/10",
  PROCESS: "border-pink-500/50 text-pink-500 bg-pink-500/10",
  USER: "border-purple-500/50 text-purple-500 bg-purple-500/10",
  FILE: "border-emerald-500/50 text-emerald-500 bg-emerald-500/10",
  NETWORK_ENDPOINT: "border-cyan-500/50 text-cyan-500 bg-cyan-500/10",
  SERVICE: "border-amber-500/50 text-amber-500 bg-amber-500/10",
  CONTAINER: "border-orange-500/50 text-orange-500 bg-orange-500/10",
};

const basePill =
  "inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] font-medium font-mono-code whitespace-nowrap";

export function EntityTypePill({ type }: { type: EntityType }) {
  return <span className={`${basePill} ${ENTITY_TYPE_TONE[type]}`}>{type}</span>;
}

export function ResolutionStatePill({ state }: { state: ResolutionState }) {
  if (state === "PROVISIONAL") {
    return (
      <span
        className={`${basePill} pl-pill-provisional bg-amber-500/10`}
        title="暂存独立实体：身份依据不足，禁止盲目合并"
      >
        {state}
      </span>
    );
  }
  if (state === "SCOPED_TEMPORAL") {
    return (
      <span className={`${basePill} border-sky-500/50 text-sky-500 bg-sky-500/10`}>{state}</span>
    );
  }
  return (
    <span className={`${basePill} border-emerald-500/50 text-emerald-500 bg-emerald-500/10`}>
      {state}
    </span>
  );
}

export function CertaintyPill({ certainty }: { certainty: Certainty }) {
  if (certainty === "CANDIDATE") {
    return (
      <span
        className={`${basePill} pl-pill-candidate bg-amber-500/10`}
        title="候选关联边：仅作线索参考，未升级为确定性事实"
      >
        {certainty} (?)
      </span>
    );
  }
  return (
    <span className={`${basePill} border-blue-500/60 text-blue-500 bg-blue-500/10`}>
      {certainty}
    </span>
  );
}

export function NormalizationStatusPill({ status }: { status: NormalizationStatus }) {
  if (status === "UNSUPPORTED_PASSTHROUGH") {
    return (
      <span
        className={`${basePill} pl-pill-candidate bg-amber-500/10`}
        title="无专用映射规则：已回退为 OCSF Base Event (class_uid=0) 留存"
      >
        {status}
      </span>
    );
  }
  return (
    <span className={`${basePill} border-emerald-500/50 text-emerald-500 bg-emerald-500/10`}>
      {status}
    </span>
  );
}

export function BatchStatusPill({ status }: { status: BatchStatus }) {
  const cls =
    status === "COMPLETED"
      ? "border-emerald-500/50 text-emerald-500 bg-emerald-500/10"
      : status === "FAILED"
        ? "border-red-500/50 text-red-500 bg-red-500/10"
        : status === "PARTIAL_FAILURE"
          ? "border-amber-500/50 text-amber-500 bg-amber-500/10"
          : "border-blue-500/50 text-blue-500 bg-blue-500/10";
  return <span className={`${basePill} ${cls}`}>{status}</span>;
}

export function StagePill({ stage }: { stage: PipelineStage }) {
  return (
    <span className={`${basePill} border-amber-500/50 text-amber-500 bg-amber-500/10`}>
      {stage}
    </span>
  );
}

const SEVERITY_TONE: Record<RuleSeverity, string> = {
  CRITICAL: "border-red-500/70 text-red-500 bg-red-500/15 font-semibold",
  HIGH: "border-orange-500/60 text-orange-500 bg-orange-500/10",
  MEDIUM: "border-amber-500/60 text-amber-500 bg-amber-500/10",
  LOW: "border-sky-500/50 text-sky-500 bg-sky-500/10",
  INFORMATIONAL: "border-slate-500/50 text-slate-400 bg-slate-500/10",
};

export function RuleSeverityPill({ severity }: { severity: RuleSeverity }) {
  return <span className={`${basePill} ${SEVERITY_TONE[severity]}`}>{severity}</span>;
}

export function RuleStatusPill({ status }: { status: RuleStatus }) {
  const cls =
    status === "ENABLED"
      ? "border-emerald-500/50 text-emerald-500 bg-emerald-500/10"
      : status === "DISABLED"
        ? "border-slate-500/50 text-slate-400 bg-slate-500/10"
        : status === "UNSUPPORTED"
          ? "pl-pill-candidate bg-amber-500/10"
          : "border-red-500/60 text-red-500 bg-red-500/10";
  return <span className={`${basePill} ${cls}`}>{status}</span>;
}

export function SignalStatusPill({ status }: { status: SignalStatus }) {
  const cls =
    status === "NEW"
      ? "border-blue-500/60 text-blue-500 bg-blue-500/10"
      : status === "OPEN"
        ? "border-amber-500/60 text-amber-500 bg-amber-500/10"
        : status === "ACKNOWLEDGED"
          ? "border-purple-500/60 text-purple-500 bg-purple-500/10"
          : status === "RESOLVED"
            ? "border-emerald-500/50 text-emerald-500 bg-emerald-500/10"
            : "border-slate-500/50 text-slate-400 bg-slate-500/10";
  return <span className={`${basePill} ${cls}`}>{status}</span>;
}
