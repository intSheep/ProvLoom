from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace

from provloom.config import CorrelationConfig
from provloom.domain.enums import Certainty, EntityType, RelationType
from provloom.domain.graph_models import CandidateRelation
from provloom.domain.ocsf_models import NormalizedEvent
from provloom.graph.interfaces import CrossSourceCorrelator
from provloom.storage.interfaces import UnitOfWork


class NetworkFiveTupleCorrelator(CrossSourceCorrelator):
    def __init__(self, uow: UnitOfWork, config: CorrelationConfig) -> None:
        self._uow = uow
        self._cfg = config

    def correlate(
        self,
        event: NormalizedEvent,
        relations: Sequence[CandidateRelation],
    ) -> Sequence[CandidateRelation]:
        out: list[CandidateRelation] = []
        for rel in relations:
            if rel.relation_type != RelationType.CONNECTS_TO or rel.five_tuple is None:
                out.append(rel)
                continue

            ft = rel.five_tuple
            has_full_5tuple = ft.src_port is not None and ft.dst_port is not None

            # Case 1: Sensor flow on verified non-NAT host IP -> attach to endpoint process edge
            if rel.evidence_role == "NETWORK_SENSOR_FLOW":
                candidates = self._uow.graph.find_network_relations_in_window(
                    tenant_scope=event.tenant_scope,
                    dst_entity_id=rel.dst_entity_id,
                    around_time=event.event_time,
                    skew_seconds=self._cfg.network_max_clock_skew_seconds,
                )
                if has_full_5tuple:
                    exact = next(
                        (
                            c
                            for c in candidates
                            if c.certainty == Certainty.DETERMINISTIC
                            and c.context_key == rel.context_key
                            and c.src_entity_id != rel.src_entity_id
                        ),
                        None,
                    )
                    if exact is not None:
                        skew_ms = round(
                            abs((event.event_time - exact.first_seen_at).total_seconds()) * 1000, 1
                        )
                        out.append(
                            replace(
                                rel,
                                src_entity_id=exact.src_entity_id,
                                correlation_rule_id="network_5tuple_v1",
                                evidence_role="NETWORK_SENSOR_5TUPLE",
                                correlation_basis={
                                    **rel.correlation_basis,
                                    "correlated_by": "network_5tuple_v1",
                                    "clock_skew_ms": skew_ms,
                                },
                            )
                        )
                        continue
                else:
                    # Partial tuple (missing src_port) on verified host IP -> CANDIDATE only.
                    dp_str = str(ft.dst_port) if ft.dst_port is not None else "*"
                    prefix = f"{ft.src_ip}:"
                    suffix = f"->{ft.dst_ip}:{dp_str}/{ft.protocol}"
                    partial = next(
                        (
                            c
                            for c in candidates
                            if c.certainty == Certainty.DETERMINISTIC
                            and c.context_key.startswith(prefix)
                            and c.context_key.endswith(suffix)
                        ),
                        None,
                    )
                    if partial is not None:
                        out.append(
                            replace(
                                rel,
                                src_entity_id=partial.src_entity_id,
                                certainty=Certainty.CANDIDATE,
                                context_key=f"candidate:{rel.context_key}",
                                correlation_rule_id="network_4tuple_candidate",
                                evidence_role="NETWORK_SENSOR_4TUPLE_CANDIDATE",
                                correlation_basis={
                                    **rel.correlation_basis,
                                    "reason": "missing_ephemeral_src_port",
                                },
                            )
                        )
                        continue

            # Case 2: Endpoint socket arrives AFTER network sensor flow -> promote sensor evidence
            elif rel.evidence_role == "ENDPOINT_SOCKET" and has_full_5tuple:
                leased_host = self._uow.entities.find_host_by_ip(
                    event.tenant_scope, ft.src_ip, event.event_time
                )
                is_nat = (
                    bool(leased_host.attributes.get("is_nat_shared", False))
                    if leased_host
                    else False
                )
                if not is_nat:
                    prior_flows = self._uow.graph.find_network_relations_in_window(
                        tenant_scope=event.tenant_scope,
                        dst_entity_id=rel.dst_entity_id,
                        around_time=event.event_time,
                        skew_seconds=self._cfg.network_max_clock_skew_seconds,
                    )
                    matching_priors = [
                        p
                        for p in prior_flows
                        if p.certainty == Certainty.DETERMINISTIC
                        and p.context_key == rel.context_key
                        and p.src_entity_id != rel.src_entity_id
                    ]
                    if matching_priors:
                        promoted = replace(
                            rel,
                            correlation_rule_id="network_5tuple_v1",
                            correlation_basis={
                                **rel.correlation_basis,
                                "correlated_by": "network_5tuple_v1",
                            },
                        )
                        for prior in matching_priors:
                            # Promote only host/endpoint sensor flows, never another process edge.
                            src_detail = self._uow.entities.find_by_identifier(
                                tenant_scope=event.tenant_scope,
                                entity_type=EntityType.NETWORK_ENDPOINT,
                                id_namespace="endpoint",
                                id_value=f"{ft.src_ip}/*",
                            )
                            allowed_src_ids = {
                                x.entity_id for x in (leased_host, src_detail) if x is not None
                            }
                            if prior.src_entity_id in allowed_src_ids:
                                self._uow.graph.promote_sensor_relation_to_process(
                                    prior.relation_id, promoted
                                )
                        out.append(promoted)
                        continue

            out.append(rel)
        return out
