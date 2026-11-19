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

export interface EventDetail extends NormalizedEventSummary {
  mapping_rule_id: string;
  ocsf_payload: Record<string, unknown>;
  unmapped_fields: Record<string, unknown>;
  raw: {
    raw_event_id: string;
    batch_id: string;
    source_id: string;
    source_type: string;
    raw_fingerprint: string;
    raw_payload: string;
    ingested_at: string;
  } | null;
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

export interface EntityDetail {
  entity: EntityDto;
  identifiers: Array<{
    identifier_id: string;
    id_namespace: string;
    id_value: string;
    is_authoritative: boolean;
    scope_entity_id: string | null;
    valid_from: string | null;
    valid_to: string | null;
    first_seen_event_id: string;
  }>;
  merges: Array<{
    merge_id: string;
    source_entity_id: string;
    target_entity_id: string;
    merge_rule_id: string;
    match_basis: Record<string, unknown>;
    evidence_event_ids: string[];
    merged_at: string;
  }>;
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
