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
