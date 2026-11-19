import type {
  AccessScopeContext,
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
  SampleImportRequest,
  SeedExamplesResponse,
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
