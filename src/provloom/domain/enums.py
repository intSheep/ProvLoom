from __future__ import annotations

from enum import Enum, IntEnum


class BatchStatus(str, Enum):
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL_FAILURE = "PARTIAL_FAILURE"
    FAILED = "FAILED"


class RawProcessStatus(str, Enum):
    PENDING = "PENDING"
    NORMALIZED = "NORMALIZED"
    NORMALIZED_FALLBACK = "NORMALIZED_FALLBACK"
    PARSE_FAILED = "PARSE_FAILED"
    NORMALIZE_FAILED = "NORMALIZE_FAILED"


class PipelineStage(str, Enum):
    INGEST = "INGEST"
    PARSE = "PARSE"
    NORMALIZE = "NORMALIZE"
    ENTITY = "ENTITY"
    GRAPH = "GRAPH"


class NormalizationStatus(str, Enum):
    MAPPED = "MAPPED"
    UNSUPPORTED_PASSTHROUGH = "UNSUPPORTED_PASSTHROUGH"


class OcsfCategoryUid(IntEnum):
    UNCATEGORIZED = 0
    SYSTEM_ACTIVITY = 1
    IAM = 3
    NETWORK_ACTIVITY = 4
    DISCOVERY = 5
    APPLICATION_ACTIVITY = 6


class OcsfClassUid(IntEnum):
    BASE_EVENT = 0
    FILE_ACTIVITY = 1001
    PROCESS_ACTIVITY = 1007
    SCRIPT_ACTIVITY = 1009
    AUTHENTICATION = 3002
    NETWORK_ACTIVITY = 4001
    HTTP_ACTIVITY = 4002
    DNS_ACTIVITY = 4003
    INVENTORY_INFO = 5001
    WEB_RESOURCES_ACTIVITY = 6001
    APPLICATION_LIFECYCLE = 6002
    API_ACTIVITY = 6003


class EntityType(str, Enum):
    HOST = "HOST"
    PROCESS = "PROCESS"
    USER = "USER"
    FILE = "FILE"
    NETWORK_ENDPOINT = "NETWORK_ENDPOINT"
    SERVICE = "SERVICE"
    CONTAINER = "CONTAINER"


class ResolutionState(str, Enum):
    RESOLVED = "RESOLVED"  # Globally/domain-authoritative strong key
    SCOPED_TEMPORAL = "SCOPED_TEMPORAL"  # Scoped to host + bounded lifecycle window
    PROVISIONAL = "PROVISIONAL"  # Ambiguous identity; kept isolated from forced merges


class RelationType(str, Enum):
    RUNS = "RUNS"
    SPAWNS = "SPAWNS"
    READS = "READS"
    WRITES = "WRITES"
    CONNECTS_TO = "CONNECTS_TO"
    AUTHENTICATES_TO = "AUTHENTICATES_TO"
    ACCESSES = "ACCESSES"
    RESOLVES = "RESOLVES"


class Certainty(str, Enum):
    DETERMINISTIC = "DETERMINISTIC"
    CANDIDATE = "CANDIDATE"


class Direction(str, Enum):
    OUTBOUND = "OUTBOUND"
    INBOUND = "INBOUND"
    BOTH = "BOTH"
