import type {
  AccessScopeContext,
  EntityDto,
  EventDetail,
  RelationDto,
  RelationEvidenceDetail,
  TimeRange,
} from "../api/types";

export interface GlobalContextBarProps {
  scope: AccessScopeContext;
  timeRange: TimeRange;
  onScopeChange: (next: AccessScopeContext) => void;
  onTimeRangeChange: (next: TimeRange) => void;
}

export interface EventTripleDiffProps {
  event: EventDetail;
}

export interface ProvenanceGraphCanvasProps {
  nodes: EntityDto[];
  edges: RelationDto[];
  includeCandidates: boolean;
  layout: "dagre" | "fcose";
  onSelectEntity: (entityId: string) => void;
  onSelectRelation: (relationId: string) => void;
}

export interface RelationEvidenceDrawerProps {
  relation: RelationDto | null;
  evidences: RelationEvidenceDetail[];
  onClose: () => void;
}
