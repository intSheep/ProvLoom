import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { detectionApi, opsApi, queryApi } from "./client";
import type {
  AccessScopeContext,
  CandidateGroupSearchRequest,
  EntitySearchRequest,
  EventSearchRequest,
  GraphTraverseRequest,
  PipelineStage,
  RawPasteImportRequest,
  ReplayRequest,
  RuleMatchSearchRequest,
  RuleSeverity,
  RuleSource,
  RuleStatus,
  RuleTestRequest,
  SampleImportRequest,
  SignalSearchRequest,
  SignalStatus,
  TimeRange,
} from "./types";

function scopeKey(scope: AccessScopeContext) {
  return {
    tenantId: scope.tenantId.trim() || "default",
    allowedSources: scope.allowedSources?.slice().sort() ?? [],
  };
}

export const provloomKeys = {
  all: ["provloom"] as const,
  metrics: (scope: AccessScopeContext) => ["provloom", "metrics", scopeKey(scope)] as const,
  batches: (scope: AccessScopeContext, limit: number) =>
    ["provloom", "batches", scopeKey(scope), limit] as const,
  failures: (
    scope: AccessScopeContext,
    params?: { batchId?: string; stage?: PipelineStage; limit?: number },
  ) => ["provloom", "failures", scopeKey(scope), params ?? {}] as const,
  mappings: (scope: AccessScopeContext) => ["provloom", "mappings", scopeKey(scope)] as const,
  events: (scope: AccessScopeContext, req: EventSearchRequest) =>
    ["provloom", "events", scopeKey(scope), req] as const,
  eventDetail: (scope: AccessScopeContext, eventId: string | null) =>
    ["provloom", "eventDetail", scopeKey(scope), eventId] as const,
  entities: (scope: AccessScopeContext, req: EntitySearchRequest) =>
    ["provloom", "entities", scopeKey(scope), req] as const,
  entityDetail: (scope: AccessScopeContext, entityId: string | null) =>
    ["provloom", "entityDetail", scopeKey(scope), entityId] as const,
  graphTraverse: (scope: AccessScopeContext, req: GraphTraverseRequest | null) =>
    ["provloom", "graph", scopeKey(scope), req] as const,
  relationEvidence: (scope: AccessScopeContext, relationId: string | null) =>
    ["provloom", "relationEvidence", scopeKey(scope), relationId] as const,
  detectionRules: (
    scope: AccessScopeContext,
    params?: {
      source?: RuleSource;
      status?: RuleStatus;
      severity?: RuleSeverity;
      attackTag?: string;
      q?: string;
    },
  ) => ["provloom", "detectionRules", scopeKey(scope), params ?? {}] as const,
  detectionRuleDetail: (scope: AccessScopeContext, ruleId: string | null) =>
    ["provloom", "detectionRuleDetail", scopeKey(scope), ruleId] as const,
  ruleMatches: (scope: AccessScopeContext, req: RuleMatchSearchRequest) =>
    ["provloom", "ruleMatches", scopeKey(scope), req] as const,
  signals: (scope: AccessScopeContext, req: SignalSearchRequest) =>
    ["provloom", "signals", scopeKey(scope), req] as const,
  signalMatches: (scope: AccessScopeContext, signalId: string | null) =>
    ["provloom", "signalMatches", scopeKey(scope), signalId] as const,
  signalEvidence: (scope: AccessScopeContext, signalId: string | null) =>
    ["provloom", "signalEvidence", scopeKey(scope), signalId] as const,
  candidateGroups: (scope: AccessScopeContext, req: CandidateGroupSearchRequest) =>
    ["provloom", "candidateGroups", scopeKey(scope), req] as const,
  candidateGroupMembers: (scope: AccessScopeContext, groupId: string | null) =>
    ["provloom", "candidateGroupMembers", scopeKey(scope), groupId] as const,
};

export function useMetricsQuery(scope: AccessScopeContext) {
  return useQuery({
    queryKey: provloomKeys.metrics(scope),
    queryFn: ({ signal }) => opsApi.getMetricsSummary(scope, signal),
  });
}

export function useBatchesQuery(scope: AccessScopeContext, limit = 50) {
  return useQuery({
    queryKey: provloomKeys.batches(scope, limit),
    queryFn: ({ signal }) => opsApi.listBatches(scope, limit, undefined, signal),
  });
}

export function useFailuresQuery(
  scope: AccessScopeContext,
  params?: { batchId?: string; stage?: PipelineStage; limit?: number },
) {
  return useQuery({
    queryKey: provloomKeys.failures(scope, params),
    queryFn: ({ signal }) => opsApi.listFailures(scope, params, signal),
  });
}

export function useMappingsQuery(scope: AccessScopeContext) {
  return useQuery({
    queryKey: provloomKeys.mappings(scope),
    queryFn: ({ signal }) => opsApi.listMappings(scope, signal),
    staleTime: 5 * 60 * 1000,
  });
}

export function useEventsSearchQuery(scope: AccessScopeContext, req: EventSearchRequest) {
  return useQuery({
    queryKey: provloomKeys.events(scope, req),
    queryFn: ({ signal }) => queryApi.searchEvents(scope, req, signal),
  });
}

export function useEventDetailQuery(scope: AccessScopeContext, eventId: string | null) {
  return useQuery({
    queryKey: provloomKeys.eventDetail(scope, eventId),
    queryFn: ({ signal }) => queryApi.getEvent(scope, eventId!, true, signal),
    enabled: Boolean(eventId),
  });
}

export function useEntitiesSearchQuery(scope: AccessScopeContext, req: EntitySearchRequest) {
  return useQuery({
    queryKey: provloomKeys.entities(scope, req),
    queryFn: ({ signal }) => queryApi.searchEntities(scope, req, signal),
  });
}

export function useEntityDetailQuery(scope: AccessScopeContext, entityId: string | null) {
  return useQuery({
    queryKey: provloomKeys.entityDetail(scope, entityId),
    queryFn: ({ signal }) => queryApi.getEntity(scope, entityId!, signal),
    enabled: Boolean(entityId),
  });
}

export function useRelationEvidenceQuery(scope: AccessScopeContext, relationId: string | null) {
  return useQuery({
    queryKey: provloomKeys.relationEvidence(scope, relationId),
    queryFn: ({ signal }) => queryApi.getRelationEvidence(scope, relationId!, 100, signal),
    enabled: Boolean(relationId),
  });
}

export function useGraphTraverseQuery(
  scope: AccessScopeContext,
  req: GraphTraverseRequest | null,
) {
  return useQuery({
    queryKey: provloomKeys.graphTraverse(scope, req),
    queryFn: ({ signal }) => queryApi.traverseGraph(scope, req!, signal),
    enabled: Boolean(req?.seed_entity_id),
  });
}

export function useInvalidateProvLoomData() {
  const qc = useQueryClient();
  return () => qc.invalidateQueries({ queryKey: provloomKeys.all });
}

export function useSeedExamplesMutation(scope: AccessScopeContext) {
  const invalidate = useInvalidateProvLoomData();
  return useMutation({
    mutationFn: () => opsApi.seedExamples(scope),
    onSuccess: () => void invalidate(),
  });
}

export function useRawImportMutation(scope: AccessScopeContext) {
  const invalidate = useInvalidateProvLoomData();
  return useMutation({
    mutationFn: (body: RawPasteImportRequest) => opsApi.importRaw(scope, body),
    onSuccess: () => void invalidate(),
  });
}

export function useSampleImportMutation(scope: AccessScopeContext) {
  const invalidate = useInvalidateProvLoomData();
  return useMutation({
    mutationFn: (body: SampleImportRequest) => opsApi.importSampleUri(scope, body),
    onSuccess: () => void invalidate(),
  });
}

export function useRetryFailuresMutation(scope: AccessScopeContext) {
  const invalidate = useInvalidateProvLoomData();
  return useMutation({
    mutationFn: (batchId?: string) => opsApi.retryFailures(scope, batchId),
    onSuccess: () => void invalidate(),
  });
}

export function useReplayMutation(scope: AccessScopeContext) {
  const invalidate = useInvalidateProvLoomData();
  return useMutation({
    mutationFn: (body: ReplayRequest) => opsApi.replayFromRaw(scope, body),
    onSuccess: () => void invalidate(),
  });
}

export function useDetectionRulesQuery(
  scope: AccessScopeContext,
  params?: {
    source?: RuleSource;
    status?: RuleStatus;
    severity?: RuleSeverity;
    attackTag?: string;
    q?: string;
  },
) {
  return useQuery({
    queryKey: provloomKeys.detectionRules(scope, params),
    queryFn: ({ signal }) => detectionApi.listRules(scope, params, signal),
  });
}

export function useDetectionRuleDetailQuery(scope: AccessScopeContext, ruleId: string | null) {
  return useQuery({
    queryKey: provloomKeys.detectionRuleDetail(scope, ruleId),
    queryFn: ({ signal }) => detectionApi.getRule(scope, ruleId!, signal),
    enabled: Boolean(ruleId),
  });
}

export function useRuleMatchesQuery(scope: AccessScopeContext, req: RuleMatchSearchRequest) {
  return useQuery({
    queryKey: provloomKeys.ruleMatches(scope, req),
    queryFn: ({ signal }) => detectionApi.searchMatches(scope, req, signal),
  });
}

export function useSignalsQuery(scope: AccessScopeContext, req: SignalSearchRequest) {
  return useQuery({
    queryKey: provloomKeys.signals(scope, req),
    queryFn: ({ signal }) => detectionApi.searchSignals(scope, req, signal),
  });
}

export function useSignalMatchesQuery(scope: AccessScopeContext, signalId: string | null) {
  return useQuery({
    queryKey: provloomKeys.signalMatches(scope, signalId),
    queryFn: ({ signal }) => detectionApi.getSignalMatches(scope, signalId!, signal),
    enabled: Boolean(signalId),
  });
}

export function useSignalEvidenceQuery(scope: AccessScopeContext, signalId: string | null) {
  return useQuery({
    queryKey: provloomKeys.signalEvidence(scope, signalId),
    queryFn: ({ signal }) => detectionApi.getSignalEvidence(scope, signalId!, signal),
    enabled: Boolean(signalId),
  });
}

export function useCandidateGroupsQuery(
  scope: AccessScopeContext,
  req: CandidateGroupSearchRequest,
) {
  return useQuery({
    queryKey: provloomKeys.candidateGroups(scope, req),
    queryFn: ({ signal }) => detectionApi.searchCandidateGroups(scope, req, signal),
  });
}

export function useCandidateGroupMembersQuery(scope: AccessScopeContext, groupId: string | null) {
  return useQuery({
    queryKey: provloomKeys.candidateGroupMembers(scope, groupId),
    queryFn: ({ signal }) => detectionApi.getCandidateGroupMembers(scope, groupId!, signal),
    enabled: Boolean(groupId),
  });
}

export function useExecuteBatchMutation(scope: AccessScopeContext) {
  const invalidate = useInvalidateProvLoomData();
  return useMutation({
    mutationFn: (params: { timeRange: TimeRange; ruleIds?: string[] }) =>
      detectionApi.executeBatch(scope, params.timeRange, params.ruleIds),
    onSuccess: () => void invalidate(),
  });
}

export function useToggleRuleMutation(scope: AccessScopeContext) {
  const invalidate = useInvalidateProvLoomData();
  return useMutation({
    mutationFn: (params: { ruleId: string; enable: boolean }) =>
      params.enable
        ? detectionApi.enableRule(scope, params.ruleId)
        : detectionApi.disableRule(scope, params.ruleId),
    onSuccess: () => void invalidate(),
  });
}

export function useImportRuleMutation(scope: AccessScopeContext) {
  const invalidate = useInvalidateProvLoomData();
  return useMutation({
    mutationFn: (params: { rawYaml: string; sourceHint?: RuleSource }) =>
      detectionApi.importRule(scope, params.rawYaml, "web-console", params.sourceHint),
    onSuccess: () => void invalidate(),
  });
}

export function useTestRuleMutation(scope: AccessScopeContext) {
  return useMutation({
    mutationFn: (body: RuleTestRequest) => detectionApi.testRule(scope, body),
  });
}

export function useUpdateSignalStatusMutation(scope: AccessScopeContext) {
  const invalidate = useInvalidateProvLoomData();
  return useMutation({
    mutationFn: (params: { signalId: string; status: SignalStatus }) =>
      detectionApi.updateSignalStatus(scope, params.signalId, params.status),
    onSuccess: () => void invalidate(),
  });
}
