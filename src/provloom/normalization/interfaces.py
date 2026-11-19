from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from provloom.domain.ocsf_models import NormalizedEvent
from provloom.domain.parsed_models import ParsedEnvelope


@dataclass(frozen=True)
class MappingSpecSummary:
    rule_id: str
    rule_version: str
    ocsf_version: str
    parser_id: str
    event_code: str | None
    category_uid: int
    class_uid: int
    activity_id: int


class OcsfMapper(Protocol):
    @property
    def spec(self) -> MappingSpecSummary: ...

    def matches(self, parsed: ParsedEnvelope) -> bool: ...

    def map_event(self, parsed: ParsedEnvelope) -> NormalizedEvent: ...


class MappingRegistry(Protocol):
    def register(self, mapper: OcsfMapper) -> None: ...
    def match(self, parsed: ParsedEnvelope) -> OcsfMapper | None: ...
    def list_specs(self) -> Sequence[MappingSpecSummary]: ...


class NormalizationService(Protocol):
    """Maps to target OCSF class or wraps into UNSUPPORTED_PASSTHROUGH (class_uid=0)."""

    def normalize(self, parsed: ParsedEnvelope) -> NormalizedEvent: ...
