export type EntityType =
  | "HOST"
  | "PROCESS"
  | "USER"
  | "FILE"
  | "NETWORK_ENDPOINT"
  | "SERVICE"
  | "CONTAINER";

export type ResolutionState = "RESOLVED" | "SCOPED_TEMPORAL" | "PROVISIONAL";

export type RelationType =
  | "RUNS"
  | "SPAWNS"
  | "READS"
  | "WRITES"
  | "CONNECTS_TO"
  | "AUTHENTICATES_TO"
  | "ACCESSES"
  | "RESOLVES";

// Visual invariant: DETERMINISTIC renders solid; CANDIDATE renders dashed amber.
export type Certainty = "DETERMINISTIC" | "CANDIDATE";

export type Direction = "OUTBOUND" | "INBOUND" | "BOTH";

export type NormalizationStatus = "MAPPED" | "UNSUPPORTED_PASSTHROUGH";

export type BatchStatus = "RUNNING" | "COMPLETED" | "PARTIAL_FAILURE" | "FAILED";

export type PipelineStage = "INGEST" | "PARSE" | "NORMALIZE" | "ENTITY" | "GRAPH";

export interface AccessScopeContext {
  tenantId: string;
  allowedSources?: string[];
}

export interface TimeRange {
  start_time: string;
  end_time: string;
}

export interface PageResponse<T> {
  items: T[];
  next_cursor: string | null;
  truncated: boolean;
}

export interface EventSearchRequest {
  time_range: TimeRange;
  sources?: string[] | null;
  class_uids?: number[] | null;
  category_uids?: number[] | null;
  field_equals?: Record<string, string | number | boolean> | null;
  include_fallback?: boolean;
  limit?: number;
  cursor?: string | null;
}

export interface NormalizedEventSummary {
  event_id: string;
  raw_event_id: string;
  source_id: string;
  ocsf_version: string;
  category_uid: number;
  class_uid: number;
  activity_id: number;
  event_time: string;
  normalization_status: NormalizationStatus;
  original_event_uid: string | null;
}

export interface RawEventDto {
  raw_event_id: string;
  batch_id: string;
  source_id: string;
  source_type: string;
  raw_fingerprint: string;
  raw_payload: string;
  ingested_at: string;
}

export interface EventDetail extends NormalizedEventSummary {
  mapping_rule_id: string;
  ocsf_payload: Record<string, unknown>;
  unmapped_fields: Record<string, unknown>;
  raw: RawEventDto | null;
}

export interface EntitySearchRequest {
  time_range?: TimeRange | null;
  entity_types?: EntityType[] | null;
  resolution_states?: ResolutionState[] | null;
  identifier_query?: string | null;
  limit?: number;
  cursor?: string | null;
}

export interface EntityDto {
  entity_id: string;
  entity_type: EntityType;
  resolution_state: ResolutionState;
  display_label: string;
  canonical_key: string | null;
  valid_from: string | null;
  valid_to: string | null;
  attributes: Record<string, unknown>;
  merged_into_id: string | null;
}

export interface EntityIdentifierDto {
  identifier_id: string;
  id_namespace: string;
  id_value: string;
  is_authoritative: boolean;
  scope_entity_id: string | null;
  valid_from: string | null;
  valid_to: string | null;
  first_seen_event_id: string;
}

export interface EntityMergeDto {
  merge_id: string;
  source_entity_id: string;
  target_entity_id: string;
  merge_rule_id: string;
  match_basis: Record<string, unknown>;
  evidence_event_ids: string[];
  merged_at: string;
}

export interface EntityDetail {
  entity: EntityDto;
  identifiers: EntityIdentifierDto[];
  merges: EntityMergeDto[];
}

export interface RelationDto {
  relation_id: string;
  src_entity_id: string;
  relation_type: RelationType;
  dst_entity_id: string;
  certainty: Certainty;
  context_key: string;
  correlation_rule_id: string;
  first_seen_at: string;
  last_seen_at: string;
  evidence_count: number;
  correlation_basis: Record<string, unknown>;
}

export interface GraphTraverseRequest {
  seed_entity_id: string;
  time_range: TimeRange;
  max_depth?: number;
  direction?: Direction;
  relation_types?: RelationType[] | null;
  include_candidates?: boolean;
  max_nodes?: number;
  max_edges?: number;
}

export interface SubgraphResponse {
  seed_entity_id: string;
  nodes: EntityDto[];
  edges: RelationDto[];
  truncated: boolean;
}

export interface RelationEvidenceDetail {
  evidence_id: string;
  relation_id: string;
  event_id: string;
  raw_event_id: string;
  evidence_role: string;
  observed_at: string;
  source_id: string;
  ocsf_class_uid: number;
  raw_payload: string;
  match_detail: Record<string, unknown>;
}

// --- Ops & Debug API (/api/v1/ops/*) ---

export interface SampleImportRequest {
  source_id: string;
  source_type: string;
  adapter_type: string;
  source_uri: string;
}

export interface RawPasteImportRequest {
  source_id: string;
  source_type: string;
  adapter_type: string;
  raw_text: string;
}

export interface IngestReceipt {
  batch_id: string;
  total_count: number;
  accepted_count: number;
  duplicate_count: number;
  failed_count: number;
}

export interface SeedExamplesResponse {
  batches_loaded: number;
  accepted_total: number;
  duplicate_total: number;
  failed_total: number;
}

export interface IngestBatchDto {
  batch_id: string;
  source_id: string;
  source_type: string;
  adapter_type: string;
  source_uri: string;
  received_at: string;
  status: BatchStatus;
  total_count: number;
  accepted_count: number;
  duplicate_count: number;
  failed_count: number;
}

export interface PipelineFailureDto {
  failure_id: string;
  batch_id: string;
  raw_event_id: string | null;
  stage: PipelineStage;
  error_code: string;
  error_message: string;
  raw_snippet: string | null;
  retryable: boolean;
  retry_count: number;
  occurred_at: string;
}

export interface RetryReceipt {
  attempted: number;
  succeeded: number;
  failed: number;
}

export interface ReplayRequest {
  time_range?: TimeRange | null;
  batch_ids?: string[] | null;
}

export interface ReplayReceipt {
  replayed_raw_events: number;
  rebuilt_entities: number;
  rebuilt_relations: number;
}

export interface PipelineMetricsSnapshot {
  ingested_total: number;
  duplicate_total: number;
  ingest_failed_total: number;
  parse_success_total: number;
  parse_failed_total: number;
  normalized_mapped_total: number;
  normalized_fallback_total: number;
  normalize_failed_total: number;
  entity_merges_total: number;
  deterministic_relations_total: number;
  candidate_relations_total: number;
  detection_rules_total: number;
  detection_rules_supported_total: number;
  detection_rules_unsupported_total: number;
  detection_executions_total: number;
  detection_matches_total: number;
  signals_created_total: number;
  signals_deduplicated_total: number;
  signals_aggregated_total: number;
  candidate_groups_created_total: number;
}

export interface MappingSpecSummary {
  rule_id: string;
  rule_version: string;
  ocsf_version: string;
  parser_id: string;
  event_code: string | null;
  category_uid: number;
  class_uid: number;
  activity_id: number;
}

// --- Detection Layer API (/api/v1/detection/*) ---

export type RuleSource = "SIGMA" | "CUSTOM";
export type RuleStatus = "ENABLED" | "DISABLED" | "UNSUPPORTED" | "ERROR";
export type RuleSeverity = "INFORMATIONAL" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type DetectionType = "EVENT" | "RELATION";
export type ExecutionMode = "BATCH" | "INCREMENTAL";
export type ExecutionStatus = "RUNNING" | "COMPLETED" | "PARTIAL_FAILURE" | "FAILED";
export type SignalStatus = "NEW" | "OPEN" | "ACKNOWLEDGED" | "RESOLVED" | "SUPPRESSED";

export interface LogsourceDto {
  category: string | null;
  product: string | null;
  service: string | null;
}

export interface RuleCompatibilityDto {
  parse_success: boolean;
  mapping_success: boolean;
  data_coverage: boolean;
  compile_success: boolean;
  execution_success: boolean | null;
  mapped_class_uids: number[];
  field_mappings: Record<string, string>;
  uncovered_fields: string[];
  unsupported_reasons: string[];
}

export interface DetectionRuleDto {
  rule_id: string;
  rule_name: string;
  source: RuleSource;
  source_reference: string;
  version: string;
  description: string;
  severity: RuleSeverity;
  attack_tags: string[];
  logsource: LogsourceDto;
  detection_type: DetectionType;
  raw_content: string;
  status: RuleStatus;
  compatibility: RuleCompatibilityDto;
  created_at: string;
  updated_at: string;
}

export interface DetectionRuleDetailDto {
  rule: DetectionRuleDto;
  compiled_sql: string | null;
  parsed_summary: Record<string, unknown> | null;
}

export interface EvidenceReferenceDto {
  event_id: string | null;
  raw_event_id: string | null;
  relation_id: string | null;
  source_id: string;
  original_event_uid: string | null;
  observed_at: string | null;
}

export interface RuleMatchDto {
  match_id: string;
  rule_id: string;
  rule_name: string;
  rule_version: string;
  severity: RuleSeverity;
  detection_type: DetectionType;
  primary_event_id: string | null;
  matched_event_ids: string[];
  primary_entity_id: string | null;
  related_entity_ids: string[];
  matched_fields: string[];
  matched_values: Record<string, unknown>;
  evidence_references: EvidenceReferenceDto[];
  source_ids: string[];
  matched_at: string;
  execution_id: string;
}

export interface RuleTestRequest {
  time_range: TimeRange;
  raw_yaml?: string | null;
  rule_id?: string | null;
  max_matches?: number;
}

export interface RuleTestResponseDto {
  rule: DetectionRuleDto;
  parsed_summary: Record<string, unknown> | null;
  field_mappings: Record<string, string>;
  compiled_sql: string | null;
  matches: RuleMatchDto[];
  failure_reason: string | null;
  duration_ms: number;
}

export interface RuleExecutionFailureDto {
  rule_id: string;
  stage: string;
  error_message: string;
}

export interface DetectionExecutionDto {
  execution_id: string;
  tenant_scope: string;
  mode: ExecutionMode;
  status: ExecutionStatus;
  time_range: TimeRange;
  rule_ids: string[];
  rules_evaluated: number;
  matches_created: number;
  matches_deduplicated: number;
  signals_created: number;
  signals_updated: number;
  candidate_groups_created: number;
  duration_ms: number;
  failures: RuleExecutionFailureDto[];
  started_at: string;
  completed_at: string | null;
}

export interface RuleMatchSearchRequest {
  time_range: TimeRange;
  rule_id?: string | null;
  detection_type?: DetectionType | null;
  severity?: RuleSeverity | null;
  entity_id?: string | null;
  limit?: number;
  cursor?: string | null;
}

export interface SignalDto {
  signal_id: string;
  signal_type: string;
  title: string;
  severity: RuleSeverity;
  status: SignalStatus;
  primary_entity_id: string | null;
  related_entity_ids: string[];
  rule_match_ids: string[];
  event_ids: string[];
  evidence_refs: EvidenceReferenceDto[];
  source_ids: string[];
  attack_tags: string[];
  first_seen_at: string;
  last_seen_at: string;
  occurrence_count: number;
  created_at: string;
  updated_at: string;
}

export interface SignalSearchRequest {
  time_range: TimeRange;
  status?: SignalStatus | null;
  severity?: RuleSeverity | null;
  entity_id?: string | null;
  signal_type?: string | null;
  limit?: number;
  cursor?: string | null;
}

export interface SignalEvidenceDetailDto {
  event_id: string;
  raw_event_id: string;
  source_id: string;
  ocsf_class_uid: number;
  event_time: string;
  original_event_uid: string | null;
  ocsf_payload: Record<string, unknown>;
  raw_payload: string;
  relation_id: string | null;
  relation_type: RelationType | null;
  certainty: Certainty | null;
}

export interface CandidateGroupDto {
  group_id: string;
  group_key: string;
  signal_ids: string[];
  rule_match_ids: string[];
  shared_entity_ids: string[];
  grouping_rule_id: string;
  grouping_basis: Record<string, unknown>;
  certainty: Certainty;
  unresolved_ambiguities: string[];
  source_ids: string[];
  first_seen_at: string;
  last_seen_at: string;
  created_at: string;
  updated_at: string;
}

export interface CandidateGroupSearchRequest {
  time_range: TimeRange;
  entity_id?: string | null;
  certainty?: Certainty | null;
  limit?: number;
  cursor?: string | null;
}

export interface CandidateGroupMembersDto {
  group: CandidateGroupDto;
  signals: SignalDto[];
  rule_matches: RuleMatchDto[];
}
