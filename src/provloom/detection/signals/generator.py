from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import NAMESPACE_URL, uuid5

from provloom.detection.domain.rule import DetectionRule, max_severity
from provloom.detection.domain.rule_match import EvidenceReference, RuleMatch
from provloom.detection.domain.signal import Signal, SignalStatus
from provloom.detection.signals.deduplicator import compute_signal_dedup_key
from provloom.storage.interfaces import UnitOfWork


@dataclass(frozen=True)
class SignalGenerationStats:
    signals_created: int = 0
    signals_aggregated: int = 0
    signals_deduplicated: int = 0


def _merge_evidence_refs(
    existing: Sequence[EvidenceReference],
    incoming: Sequence[EvidenceReference],
) -> tuple[EvidenceReference, ...]:
    seen: set[tuple[str, str, str]] = set()
    merged: list[EvidenceReference] = []
    for ref in (*existing, *incoming):
        key = (
            str(ref.event_id or ""),
            str(ref.raw_event_id or ""),
            str(ref.relation_id or ""),
        )
        if key not in seen:
            seen.add(key)
            merged.append(ref)
    return tuple(merged)


class SignalGenerator:
    """Projects immutable RuleMatches into deduplicated, entity-scoped Signals."""

    def ingest_matches(
        self,
        uow: UnitOfWork,
        rule: DetectionRule,
        matches: Sequence[RuleMatch],
        now: datetime | None = None,
    ) -> SignalGenerationStats:
        ts = now or datetime.now(UTC)
        created = 0
        aggregated = 0
        deduped = 0

        for match in matches:
            sig_dedup = compute_signal_dedup_key(
                tenant_scope=match.tenant_scope,
                rule_id=match.rule_id,
                primary_entity_id=match.primary_entity_id,
                primary_event_id=match.primary_event_id,
            )
            existing = uow.detection.get_signal_by_dedup_key(match.tenant_scope, sig_dedup)
            if existing is None:
                sig_id = uuid5(NAMESPACE_URL, f"provloom:signal:{sig_dedup}")
                sig = Signal(
                    signal_id=sig_id,
                    tenant_scope=match.tenant_scope,
                    dedup_key=sig_dedup,
                    signal_type=f"rule:{rule.rule_id}",
                    title=rule.rule_name,
                    severity=match.severity,
                    status=SignalStatus.NEW,
                    primary_entity_id=match.primary_entity_id,
                    related_entity_ids=match.related_entity_ids,
                    rule_match_ids=(match.match_id,),
                    event_ids=match.matched_event_ids,
                    evidence_refs=match.evidence_references,
                    source_ids=match.source_ids,
                    attack_tags=rule.attack_tags,
                    first_seen_at=match.matched_at,
                    last_seen_at=match.matched_at,
                    occurrence_count=1,
                    created_at=ts,
                    updated_at=ts,
                )
                uow.detection.save_signal(sig)
                created += 1
                continue

            if match.match_id in existing.rule_match_ids:
                deduped += 1
                continue

            new_match_ids = tuple(dict.fromkeys((*existing.rule_match_ids, match.match_id)))
            new_event_ids = tuple(dict.fromkeys((*existing.event_ids, *match.matched_event_ids)))
            new_rel_ents = tuple(
                x
                for x in dict.fromkeys((*existing.related_entity_ids, *match.related_entity_ids))
                if x != existing.primary_entity_id
            )
            new_sources = tuple(dict.fromkeys((*existing.source_ids, *match.source_ids)))
            new_tags = tuple(dict.fromkeys((*existing.attack_tags, *rule.attack_tags)))
            updated_sig = Signal(
                signal_id=existing.signal_id,
                tenant_scope=existing.tenant_scope,
                dedup_key=existing.dedup_key,
                signal_type=existing.signal_type,
                title=existing.title,
                severity=max_severity(existing.severity, match.severity),
                status=existing.status,
                primary_entity_id=existing.primary_entity_id,
                related_entity_ids=new_rel_ents,
                rule_match_ids=new_match_ids,
                event_ids=new_event_ids,
                evidence_refs=_merge_evidence_refs(
                    existing.evidence_refs, match.evidence_references
                ),
                source_ids=new_sources,
                attack_tags=new_tags,
                first_seen_at=min(existing.first_seen_at, match.matched_at),
                last_seen_at=max(existing.last_seen_at, match.matched_at),
                occurrence_count=len(new_match_ids),
                created_at=existing.created_at,
                updated_at=ts,
            )
            uow.detection.save_signal(updated_sig)
            aggregated += 1

        return SignalGenerationStats(
            signals_created=created,
            signals_aggregated=aggregated,
            signals_deduplicated=deduped,
        )
