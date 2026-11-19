from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from provloom.domain.entity_models import EntityObservation, EntityResolutionResult
from provloom.domain.ocsf_models import NormalizedEvent


class EntityExtractor(Protocol):
    def supports_class(self, class_uid: int) -> bool: ...
    def extract(self, event: NormalizedEvent) -> Sequence[EntityObservation]: ...


class IdentityResolver(Protocol):
    """Resolves entity identity with host/lifecycle scoping and records deterministic merges."""

    def resolve(
        self,
        event: NormalizedEvent,
        observations: Sequence[EntityObservation],
    ) -> EntityResolutionResult: ...
