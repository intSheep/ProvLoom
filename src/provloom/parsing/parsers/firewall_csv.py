from __future__ import annotations

from provloom.domain.errors import LogParseError
from provloom.domain.parsed_models import ParsedEnvelope
from provloom.domain.raw_models import RawEvent
from provloom.parsing.interfaces import LogParser
from provloom.parsing.parsers.common import coerce_optional_int, decode_raw_object
from provloom.parsing.time_utils import parse_utc_timestamp


class FirewallParser(LogParser):
    @property
    def parser_id(self) -> str:
        return "firewall"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    def supports(self, raw_event: RawEvent) -> bool:
        return raw_event.source_type.lower() in {"firewall", "firewall_csv", "fw"}

    def parse(self, raw_event: RawEvent) -> ParsedEnvelope:
        fields = decode_raw_object(raw_event)
        if not fields.get("src_ip") or not fields.get("dst_ip"):
            raise LogParseError("Firewall log missing src_ip or dst_ip")

        occurred_at = parse_utc_timestamp(fields.get("timestamp") or fields.get("time"))
        for k in ("src_port", "dst_port", "bytes_sent", "bytes_received"):
            if k in fields:
                fields[k] = coerce_optional_int(fields[k])

        orig_uid = fields.get("event_uid") or raw_event.external_event_uid
        return ParsedEnvelope(
            raw_event_id=raw_event.raw_event_id,
            tenant_scope=raw_event.tenant_scope,
            source_id=raw_event.source_id,
            parser_id=self.parser_id,
            parser_version=self.parser_version,
            occurred_at=occurred_at,
            event_code="flow",
            vendor="Generic",
            product="Network Firewall",
            original_event_uid=str(orig_uid) if orig_uid is not None else None,
            extracted_fields=fields,
        )
