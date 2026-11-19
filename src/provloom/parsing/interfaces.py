from __future__ import annotations

from typing import Protocol

from provloom.domain.parsed_models import ParsedEnvelope
from provloom.domain.raw_models import RawEvent


class LogParser(Protocol):
    """Extracts source fields and timestamps without performing attack classification."""

    @property
    def parser_id(self) -> str: ...

    @property
    def parser_version(self) -> str: ...

    def supports(self, raw_event: RawEvent) -> bool: ...

    def parse(self, raw_event: RawEvent) -> ParsedEnvelope: ...


class ParserRegistry(Protocol):
    def register(self, parser: LogParser) -> None: ...
    def resolve(self, raw_event: RawEvent) -> LogParser: ...
