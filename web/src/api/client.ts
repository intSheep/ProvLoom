import type {
  AccessScopeContext,
  CandidateGroupDto,
  CandidateGroupMembersDto,
  CandidateGroupSearchRequest,
  DetectionExecutionDto,
  DetectionRuleDetailDto,
  DetectionRuleDto,
  Direction,
  EntityDetail,
  EntityDto,
  EntitySearchRequest,
  EventDetail,
  EventSearchRequest,
  GraphTraverseRequest,
  IngestBatchDto,
  IngestReceipt,
  MappingSpecSummary,
  NormalizedEventSummary,
  PageResponse,
  PipelineFailureDto,
  PipelineMetricsSnapshot,
  PipelineStage,
  RawPasteImportRequest,
  RelationDto,
  RelationEvidenceDetail,
  RelationType,
  ReplayReceipt,
  ReplayRequest,
  RetryReceipt,
  RuleMatchDto,
  RuleMatchSearchRequest,
  RuleSeverity,
  RuleSource,
  RuleStatus,
  RuleTestRequest,
  RuleTestResponseDto,
  SampleImportRequest,
  SeedExamplesResponse,
  SignalDto,
  SignalEvidenceDetailDto,
  SignalSearchRequest,
  SignalStatus,
  SubgraphResponse,
  TimeRange,
} from "./types";

export class ProvLoomApiError extends Error {
  readonly status: number;
  readonly detail: string;

  constructor(status: number, detail: string) {
    super(`HTTP ${status}: ${detail}`);
    this.name = "ProvLoomApiError";
    this.status = status;
    this.detail = detail;
  }
}

export function buildScopeHeaders(scope: AccessScopeContext): Record<string, string> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Tenant-Id": scope.tenantId.trim() || "default",
  };
  if (scope.allowedSources?.length) {
    headers["X-Allowed-Sources"] = scope.allowedSources.join(",");
  }
  return headers;
}

export async function apiFetch<T>(
  path: string,
  scope: AccessScopeContext,
  init?: RequestInit,
): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: {
      ...buildScopeHeaders(scope),
      ...(init?.headers ?? {}),
    },
  });
  if (!res.ok) {
    const raw = await res.text();
    let detail = raw;
    try {
      const parsed = JSON.parse(raw) as { detail?: string };
      if (typeof parsed.detail === "string") {
        detail = parsed.detail;
      }
    } catch {
      // Keep plain text payload when response is not JSON.
    }
    throw new ProvLoomApiError(res.status, detail || res.statusText);
  }
  return (await res.json()) as T;
}

export const queryApi = {
  searchEvents(scope: AccessScopeContext, body: EventSearchRequest, signal?: AbortSignal) {
    return apiFetch<PageResponse<NormalizedEventSummary>>("/api/v1/events/search", scope, {
      method: "POST",
      body: JSON.stringify(body),
      signal,
    });
  },

  getEvent(
    scope: AccessScopeContext,
    eventId: string,
    includeRaw = true,
    signal?: AbortSignal,
  ) {
    return apiFetch<EventDetail>(
      `/api/v1/events/${encodeURIComponent(eventId)}?include_raw=${includeRaw}`,
      scope,
      { signal },
    );
  },

  searchEntities(scope: AccessScopeContext, body: EntitySearchRequest, signal?: AbortSignal) {
    return apiFetch<PageResponse<EntityDto>>("/api/v1/entities/search", scope, {
      method: "POST",
      body: JSON.stringify(body),
      signal,
    });
  },

  getEntity(scope: AccessScopeContext, entityId: string, signal?: AbortSignal) {
    return apiFetch<EntityDetail>(`/api/v1/entities/${encodeURIComponent(entityId)}`, scope, {
      signal,
    });
  },

  getEntityRelations(
    scope: AccessScopeContext,
    entityId: string,
    params: {
      timeRange: TimeRange;
      direction?: Direction;
      relationTypes?: RelationType[];
      includeCandidates?: boolean;
      limit?: number;
      cursor?: string;
    },
    signal?: AbortSignal,
  ) {
    const qs = new URLSearchParams({
      start_time: params.timeRange.start_time,
      end_time: params.timeRange.end_time,
      direction: params.direction ?? "BOTH",
      include_candidates: String(params.includeCandidates ?? false),
      limit: String(params.limit ?? 100),
    });
    if (params.cursor) qs.set("cursor", params.cursor);
    for (const rt of params.relationTypes ?? []) {
      qs.append("relation_types", rt);
    }
    return apiFetch<PageResponse<RelationDto>>(
      `/api/v1/entities/${encodeURIComponent(entityId)}/relations?${qs.toString()}`,
      scope,
      { signal },
    );
  },

  traverseGraph(scope: AccessScopeContext, body: GraphTraverseRequest, signal?: AbortSignal) {
    return apiFetch<SubgraphResponse>("/api/v1/graph/traverse", scope, {
      method: "POST",
      body: JSON.stringify(body),
      signal,
    });
  },

  getRelationEvidence(
    scope: AccessScopeContext,
    relationId: string,
    limit = 100,
    signal?: AbortSignal,
  ) {
    return apiFetch<PageResponse<RelationEvidenceDetail>>(
      `/api/v1/relations/${encodeURIComponent(relationId)}/evidence?limit=${limit}`,
      scope,
      { signal },
    );
  },
};

export const opsApi = {
  getMetricsSummary(scope: AccessScopeContext, signal?: AbortSignal) {
    return apiFetch<PipelineMetricsSnapshot>("/api/v1/ops/metrics/summary", scope, { signal });
  },

  getTimeBounds(scope: AccessScopeContext, signal?: AbortSignal) {
    return apiFetch<TimeRange | null>("/api/v1/ops/time-bounds", scope, { signal });
  },

  listBatches(scope: AccessScopeContext, limit = 50, cursor?: string, signal?: AbortSignal) {
    const qs = new URLSearchParams({ limit: String(limit) });
    if (cursor) qs.set("cursor", cursor);
    return apiFetch<PageResponse<IngestBatchDto>>(`/api/v1/ops/batches?${qs.toString()}`, scope, {
      signal,
    });
  },

  listFailures(
    scope: AccessScopeContext,
    params?: { batchId?: string; stage?: PipelineStage; limit?: number; cursor?: string },
    signal?: AbortSignal,
  ) {
    const qs = new URLSearchParams({ limit: String(params?.limit ?? 100) });
    if (params?.batchId) qs.set("batch_id", params.batchId);
    if (params?.stage) qs.set("stage", params.stage);
    if (params?.cursor) qs.set("cursor", params.cursor);
    return apiFetch<PageResponse<PipelineFailureDto>>(
      `/api/v1/ops/failures?${qs.toString()}`,
      scope,
      { signal },
    );
  },

  listMappings(scope: AccessScopeContext, signal?: AbortSignal) {
    return apiFetch<MappingSpecSummary[]>("/api/v1/ops/mappings", scope, { signal });
  },

  seedExamples(scope: AccessScopeContext) {
    return apiFetch<SeedExamplesResponse>("/api/v1/ops/batches/examples", scope, {
      method: "POST",
    });
  },

  importRaw(scope: AccessScopeContext, body: RawPasteImportRequest) {
    return apiFetch<IngestReceipt>("/api/v1/ops/batches/raw", scope, {
      method: "POST",
      body: JSON.stringify(body),
    });
  },

  importSampleUri(scope: AccessScopeContext, body: SampleImportRequest) {
    return apiFetch<IngestReceipt>("/api/v1/ops/batches/import", scope, {
      method: "POST",
      body: JSON.stringify(body),
    });
  },

  retryFailures(scope: AccessScopeContext, batchId?: string) {
    const qs = batchId ? `?batch_id=${encodeURIComponent(batchId)}` : "";
    return apiFetch<RetryReceipt>(`/api/v1/ops/retry${qs}`, scope, { method: "POST" });
  },

  replayFromRaw(scope: AccessScopeContext, body: ReplayRequest) {
    return apiFetch<ReplayReceipt>("/api/v1/ops/replay", scope, {
      method: "POST",
      body: JSON.stringify(body),
    });
  },
};

export const detectionApi = {
  listRules(
    scope: AccessScopeContext,
    params?: {
      source?: RuleSource;
      status?: RuleStatus;
      severity?: RuleSeverity;
      attackTag?: string;
      q?: string;
      limit?: number;
      cursor?: string;
    },
    signal?: AbortSignal,
  ) {
    const qs = new URLSearchParams({ limit: String(params?.limit ?? 200) });
    if (params?.source) qs.set("source", params.source);
    if (params?.status) qs.set("status", params.status);
    if (params?.severity) qs.set("severity", params.severity);
    if (params?.attackTag) qs.set("attack_tag", params.attackTag);
    if (params?.q) qs.set("q", params.q);
    if (params?.cursor) qs.set("cursor", params.cursor);
    return apiFetch<PageResponse<DetectionRuleDto>>(
      `/api/v1/detection/rules?${qs.toString()}`,
      scope,
      { signal },
    );
  },

  getRule(scope: AccessScopeContext, ruleId: string, signal?: AbortSignal) {
    return apiFetch<DetectionRuleDetailDto>(
      `/api/v1/detection/rules/${encodeURIComponent(ruleId)}`,
      scope,
      { signal },
    );
  },

  validateRule(scope: AccessScopeContext, rawYaml: string, sourceHint?: RuleSource) {
    return apiFetch<DetectionRuleDetailDto>("/api/v1/detection/rules/validate", scope, {
      method: "POST",
      body: JSON.stringify({ raw_yaml: rawYaml, source_hint: sourceHint ?? null }),
    });
  },

  importRule(
    scope: AccessScopeContext,
    rawYaml: string,
    sourceReference = "web-console",
    sourceHint?: RuleSource,
  ) {
    return apiFetch<DetectionRuleDetailDto>("/api/v1/detection/rules/import", scope, {
      method: "POST",
      body: JSON.stringify({
        raw_yaml: rawYaml,
        source_reference: sourceReference,
        source_hint: sourceHint ?? null,
      }),
    });
  },

  enableRule(scope: AccessScopeContext, ruleId: string) {
    return apiFetch<DetectionRuleDto>(
      `/api/v1/detection/rules/${encodeURIComponent(ruleId)}/enable`,
      scope,
      { method: "POST" },
    );
  },

  disableRule(scope: AccessScopeContext, ruleId: string) {
    return apiFetch<DetectionRuleDto>(
      `/api/v1/detection/rules/${encodeURIComponent(ruleId)}/disable`,
      scope,
      { method: "POST" },
    );
  },

  testRule(scope: AccessScopeContext, body: RuleTestRequest) {
    return apiFetch<RuleTestResponseDto>("/api/v1/detection/rules/test", scope, {
      method: "POST",
      body: JSON.stringify(body),
    });
  },

  executeRule(scope: AccessScopeContext, ruleId: string, timeRange: TimeRange) {
    return apiFetch<DetectionExecutionDto>(
      `/api/v1/detection/execute/${encodeURIComponent(ruleId)}`,
      scope,
      {
        method: "POST",
        body: JSON.stringify({ time_range: timeRange }),
      },
    );
  },

  executeBatch(scope: AccessScopeContext, timeRange: TimeRange, ruleIds?: string[]) {
    return apiFetch<DetectionExecutionDto>("/api/v1/detection/execute-batch", scope, {
      method: "POST",
      body: JSON.stringify({ time_range: timeRange, rule_ids: ruleIds ?? null }),
    });
  },

  searchMatches(scope: AccessScopeContext, body: RuleMatchSearchRequest, signal?: AbortSignal) {
    return apiFetch<PageResponse<RuleMatchDto>>("/api/v1/detection/matches/search", scope, {
      method: "POST",
      body: JSON.stringify(body),
      signal,
    });
  },

  searchSignals(scope: AccessScopeContext, body: SignalSearchRequest, signal?: AbortSignal) {
    return apiFetch<PageResponse<SignalDto>>("/api/v1/detection/signals/search", scope, {
      method: "POST",
      body: JSON.stringify(body),
      signal,
    });
  },

  getSignalMatches(scope: AccessScopeContext, signalId: string, signal?: AbortSignal) {
    return apiFetch<RuleMatchDto[]>(
      `/api/v1/detection/signals/${encodeURIComponent(signalId)}/matches`,
      scope,
      { signal },
    );
  },

  getSignalEvidence(scope: AccessScopeContext, signalId: string, signal?: AbortSignal) {
    return apiFetch<SignalEvidenceDetailDto[]>(
      `/api/v1/detection/signals/${encodeURIComponent(signalId)}/evidence`,
      scope,
      { signal },
    );
  },

  updateSignalStatus(scope: AccessScopeContext, signalId: string, status: SignalStatus) {
    return apiFetch<SignalDto>(
      `/api/v1/detection/signals/${encodeURIComponent(signalId)}/status`,
      scope,
      {
        method: "PATCH",
        body: JSON.stringify({ status }),
      },
    );
  },

  searchCandidateGroups(
    scope: AccessScopeContext,
    body: CandidateGroupSearchRequest,
    signal?: AbortSignal,
  ) {
    return apiFetch<PageResponse<CandidateGroupDto>>(
      "/api/v1/detection/candidate-groups/search",
      scope,
      {
        method: "POST",
        body: JSON.stringify(body),
        signal,
      },
    );
  },

  getCandidateGroupMembers(scope: AccessScopeContext, groupId: string, signal?: AbortSignal) {
    return apiFetch<CandidateGroupMembersDto>(
      `/api/v1/detection/candidate-groups/${encodeURIComponent(groupId)}/members`,
      scope,
      { signal },
    );
  },
};
