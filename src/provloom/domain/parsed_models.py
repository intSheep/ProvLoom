from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID


@dataclass(frozen=True)
class ParsedEnvelope:
    """In-memory intermediate representation emitted by LogParser (no attack semantics)."""

    raw_event_id: UUID
    tenant_scope: str
    source_id: str
    parser_id: str
    parser_version: str
    occurred_at: datetime
    event_code: str | None = None
    vendor: str | None = None
    product: str | None = None
    original_event_uid: str | None = None
    extracted_fields: dict[str, Any] = field(default_factory=dict)
