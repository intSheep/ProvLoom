from __future__ import annotations

from provloom.domain.errors import LogParseError
from provloom.domain.parsed_models import ParsedEnvelope
from provloom.domain.raw_models import RawEvent
from provloom.parsing.interfaces import LogParser
from provloom.parsing.parsers.common import coerce_optional_int, decode_raw_object
from provloom.parsing.time_utils import parse_utc_timestamp


class AssetManifestParser(LogParser):
    @property
    def parser_id(self) -> str:
        return "asset"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    def supports(self, raw_event: RawEvent) -> bool:
        return raw_event.source_type.lower() in {"asset", "assets", "cmdb", "inventory"}

    def parse(self, raw_event: RawEvent) -> ParsedEnvelope:
        fields = decode_raw_object(raw_event)
        if not any(fields.get(k) for k in ("asset_id", "hostname", "container_id", "service_name")):
            raise LogParseError("Asset manifest record missing identifying asset keys")

        ts_candidate = (
            fields.get("observed_at") or fields.get("valid_from") or fields.get("timestamp")
        )
        occurred_at = parse_utc_timestamp(ts_candidate) if ts_candidate else raw_event.ingested_at
        if "listen_port" in fields:
            fields["listen_port"] = coerce_optional_int(fields["listen_port"])
        if isinstance(fields.get("is_nat_shared"), str):
            fields["is_nat_shared"] = fields["is_nat_shared"].lower() in {"true", "1", "yes"}

        orig_uid = (
            fields.get("asset_id") or fields.get("container_id") or raw_event.external_event_uid
        )
        return ParsedEnvelope(
            raw_event_id=raw_event.raw_event_id,
            tenant_scope=raw_event.tenant_scope,
            source_id=raw_event.source_id,
            parser_id=self.parser_id,
            parser_version=self.parser_version,
            occurred_at=occurred_at,
            event_code="inventory",
            vendor="CMDB",
            product="AssetInventory",
            original_event_uid=str(orig_uid) if orig_uid is not None else None,
            extracted_fields=fields,
        )
