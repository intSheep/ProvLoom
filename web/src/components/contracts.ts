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
  event: EventDetail | null;
  isLoading?: boolean;
  error?: Error | null;
  open: boolean;
  onClose: () => void;
}

export type GraphLayoutMode = "dagre" | "dagre-tb" | "fcose";

export interface ProvenanceGraphCanvasProps {
  nodes: EntityDto[];
  edges: RelationDto[];
  seedEntityId?: string | null;
  selectedEntityId?: string | null;
  selectedRelationId?: string | null;
  includeCandidates: boolean;
  layout: GraphLayoutMode;
  onLayoutChange?: (next: GraphLayoutMode) => void;
  onSelectEntity: (entityId: string) => void;
  onExpandEntity?: (entityId: string) => void;
  onSelectRelation: (relationId: string) => void;
}

export interface RelationEvidenceDrawerProps {
  relation: RelationDto | null;
  evidences: RelationEvidenceDetail[];
  isLoading?: boolean;
  error?: Error | null;
  onClose: () => void;
}
