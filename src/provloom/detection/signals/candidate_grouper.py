from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

from provloom.detection.domain.candidate_group import CandidateGroup, CandidateGroupingConfig
from provloom.detection.domain.signal import Signal, SignalStatus
from provloom.domain.common import AccessScope, PageSpec, TimeRange
from provloom.domain.entity_models import Entity
from provloom.domain.enums import Certainty, Direction, ResolutionState
from provloom.storage.interfaces import UnitOfWork


def _within_gap(a: Signal, b: Signal, max_gap_seconds: float) -> bool:
    latest_start = max(a.first_seen_at, b.first_seen_at)
    earliest_end = min(a.last_seen_at, b.last_seen_at)
    if latest_start <= earliest_end:
        return True
    return (latest_start - earliest_end).total_seconds() <= max_gap_seconds


class CandidateGrouper:
    """Clusters active Signals via deterministic entity/relation links without mutating facts."""

    def __init__(self, config: CandidateGroupingConfig | None = None) -> None:
        self._cfg = config or CandidateGroupingConfig()

    def build_groups(
        self,
        uow: UnitOfWork,
        scope: AccessScope,
        time_range: TimeRange,
        now: datetime | None = None,
    ) -> int:
        if not self._cfg.enabled:
            return 0

        ts = now or datetime.now(UTC)
        signals = [
            s
            for s in uow.detection.list_signals_in_window(scope, time_range)
            if s.status != SignalStatus.SUPPRESSED
        ]
        if len(signals) < 2:
            return 0

        entity_cache: dict[UUID, Entity] = {}
        for sig in signals:
            for eid in (sig.primary_entity_id, *sig.related_entity_ids):
                if eid is not None and eid not in entity_cache:
                    det = uow.entities.get_detail(scope, eid, follow_merged=True)
                    if det is not None:
                        entity_cache[eid] = det.entity

        det_adj: dict[UUID, dict[UUID, tuple[UUID, str]]] = {}
        cand_neighbors: dict[UUID, list[str]] = {}
        primary_ids = {s.primary_entity_id for s in signals if s.primary_entity_id is not None}
        for pid in primary_ids:
            rels = uow.graph.get_entity_relations(
                scope=scope,
                entity_id=pid,
                time_range=time_range,
                direction=Direction.BOTH,
                relation_types=None,
                include_candidates=True,
                page=PageSpec(limit=200),
            ).items
            for rel in rels:
                other = rel.dst_entity_id if rel.src_entity_id == pid else rel.src_entity_id
                if rel.certainty == Certainty.DETERMINISTIC:
                    det_adj.setdefault(pid, {})[other] = (
                        rel.relation_id,
                        rel.relation_type.value,
                    )
                else:
                    cand_neighbors.setdefault(pid, []).append(
                        f"CANDIDATE {rel.relation_type.value} edge ({rel.relation_id}) on {pid}"
                    )

        parent = list(range(len(signals)))

        def _find(i: int) -> int:
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        def _union(i: int, j: int) -> None:
            ri, rj = _find(i), _find(j)
            if ri != rj:
                parent[rj] = ri

        pair_reasons: dict[tuple[int, int], dict[str, Any]] = {}
        for i in range(len(signals)):
            for j in range(i + 1, len(signals)):
                sa, sb = signals[i], signals[j]
                if not _within_gap(sa, sb, self._cfg.max_time_gap_seconds):
                    continue
                pa, pb = sa.primary_entity_id, sb.primary_entity_id
                if pa is None or pb is None:
                    continue

                ent_a = entity_cache.get(pa)
                ent_b = entity_cache.get(pb)
                if ent_a is None or ent_b is None:
                    continue
                # Never deterministically merge across ambiguous PROVISIONAL identities.
                if (
                    ent_a.resolution_state == ResolutionState.PROVISIONAL
                    or ent_b.resolution_state == ResolutionState.PROVISIONAL
                ):
                    continue

                if self._cfg.group_by_shared_entity and pa == pb:
                    _union(i, j)
                    pair_reasons[(i, j)] = {
                        "basis": "shared_primary_entity",
                        "entity_id": str(pa),
                        "entity_label": ent_a.display_label,
                    }
                elif self._cfg.group_by_direct_deterministic_relation and pb in det_adj.get(pa, {}):
                    rel_id, rel_type = det_adj[pa][pb]
                    _union(i, j)
                    pair_reasons[(i, j)] = {
                        "basis": "direct_deterministic_relation",
                        "relation_id": str(rel_id),
                        "relation_type": rel_type,
                        "src_entity_id": str(pa),
                        "dst_entity_id": str(pb),
                    }

        clusters: dict[int, list[int]] = {}
        for idx in range(len(signals)):
            clusters.setdefault(_find(idx), []).append(idx)

        created_count = 0
        for member_indices in clusters.values():
            if len(member_indices) < 2:
                continue
            member_sigs = [signals[i] for i in member_indices]
            sig_ids = tuple(s.signal_id for s in member_sigs)
            match_ids = tuple(dict.fromkeys(mid for s in member_sigs for mid in s.rule_match_ids))
            shared_ents = tuple(
                dict.fromkeys(
                    s.primary_entity_id for s in member_sigs if s.primary_entity_id is not None
                )
            )
            sources = tuple(dict.fromkeys(src for s in member_sigs for src in s.source_ids))

            reasons: list[dict[str, Any]] = []
            idx_set = set(member_indices)
            for (ia, ib), rinfo in pair_reasons.items():
                if ia in idx_set and ib in idx_set:
                    reasons.append(rinfo)

            ambiguities: list[str] = []
            for s in member_sigs:
                if s.primary_entity_id and s.primary_entity_id in cand_neighbors:
                    ambiguities.extend(cand_neighbors[s.primary_entity_id])
                for reid in s.related_entity_ids:
                    rent = entity_cache.get(reid)
                    if rent and rent.resolution_state == ResolutionState.PROVISIONAL:
                        ambiguities.append(
                            f"Related entity {rent.display_label!r} ({reid}) is PROVISIONAL"
                        )

            anchor_str = ",".join(sorted(str(e) for e in shared_ents))
            group_key = hashlib.sha256(
                f"{scope.tenant_id}|entities:{anchor_str}".encode()
            ).hexdigest()[:40]
            group_id = uuid5(NAMESPACE_URL, f"provloom:candgroup:{scope.tenant_id}:{group_key}")

            basis_types = {r["basis"] for r in reasons}
            rule_id = (
                "shared_entity_and_1hop_relation"
                if len(basis_types) > 1
                else next(iter(basis_types), "deterministic_entity_cluster")
            )

            group = CandidateGroup(
                group_id=group_id,
                tenant_scope=scope.tenant_id,
                group_key=group_key,
                signal_ids=sig_ids,
                rule_match_ids=match_ids,
                shared_entity_ids=shared_ents,
                grouping_rule_id=rule_id,
                grouping_basis={
                    "links": reasons,
                    "max_time_gap_seconds": self._cfg.max_time_gap_seconds,
                    "signal_types": list(dict.fromkeys(s.signal_type for s in member_sigs)),
                },
                certainty=Certainty.DETERMINISTIC,
                unresolved_ambiguities=tuple(dict.fromkeys(ambiguities)),
                source_ids=sources,
                first_seen_at=min(s.first_seen_at for s in member_sigs),
                last_seen_at=max(s.last_seen_at for s in member_sigs),
                created_at=ts,
                updated_at=ts,
            )
            if uow.detection.upsert_candidate_group(group):
                created_count += 1

        return created_count
