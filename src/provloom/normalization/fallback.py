from __future__ import annotations

from uuid import NAMESPACE_URL, uuid5

from provloom.domain.enums import NormalizationStatus, OcsfCategoryUid, OcsfClassUid
from provloom.domain.ocsf_models import NormalizedEvent
from provloom.domain.parsed_models import ParsedEnvelope


def build_deterministic_event_id(parsed: ParsedEnvelope) -> object:
    return uuid5(NAMESPACE_URL, f"provloom:event:{parsed.raw_event_id}")


class FallbackNormalizer:
    """Wraps unsupported events into OCSF Base Event (class_uid=0) with zero silent drops."""

    def __init__(self, ocsf_version: str = "1.4.0") -> None:
        self._version = ocsf_version

    def wrap(self, parsed: ParsedEnvelope) -> NormalizedEvent:
        ev_id = uuid5(NAMESPACE_URL, f"provloom:event:{parsed.raw_event_id}")
        unmapped = dict(parsed.extracted_fields)
        payload = {
            "category_uid": int(OcsfCategoryUid.UNCATEGORIZED),
            "class_uid": int(OcsfClassUid.BASE_EVENT),
            "activity_id": 0,
            "type_uid": 0,
            "severity_id": 0,
            "time": int(parsed.occurred_at.timestamp() * 1000),
            "metadata": {
                "version": self._version,
                "uid": str(ev_id),
                "original_uid": parsed.original_event_uid,
                "product": {
                    "vendor_name": parsed.vendor or "Unknown",
                    "name": parsed.product or parsed.parser_id,
                },
            },
            "unmapped": unmapped,
        }
        return NormalizedEvent(
            event_id=ev_id,
            raw_event_id=parsed.raw_event_id,
            tenant_scope=parsed.tenant_scope,
            source_id=parsed.source_id,
            ocsf_version=self._version,
            category_uid=int(OcsfCategoryUid.UNCATEGORIZED),
            class_uid=int(OcsfClassUid.BASE_EVENT),
            activity_id=0,
            event_time=parsed.occurred_at,
            normalization_status=NormalizationStatus.UNSUPPORTED_PASSTHROUGH,
            mapping_rule_id="fallback_passthrough_0",
            original_event_uid=parsed.original_event_uid,
            ocsf_payload=payload,
            unmapped_fields=unmapped,
        )
