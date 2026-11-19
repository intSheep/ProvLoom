from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from provloom.domain.entity_models import EntityResolutionResult
from provloom.domain.enums import Certainty, OcsfClassUid, RelationType
from provloom.domain.graph_models import CandidateRelation, FiveTuple
from provloom.domain.ocsf_models import NormalizedEvent
from provloom.graph.interfaces import RelationExtractor


class OcsfRelationExtractor(RelationExtractor):
    def supports_class(self, class_uid: int) -> bool:
        return class_uid != int(OcsfClassUid.BASE_EVENT)

    def extract(
        self,
        event: NormalizedEvent,
        resolved: EntityResolutionResult,
    ) -> Sequence[CandidateRelation]:
        roles = resolved.by_role
        p = event.ocsf_payload
        out: list[CandidateRelation] = []

        host = roles.get("host")
        container = roles.get("container")
        actor_proc = roles.get("actor_process")
        parent_proc = roles.get("parent_process")

        # Host / Container -> Process execution context
        runner = container or host
        if runner is not None and parent_proc is not None:
            out.append(
                self._rel(
                    event=event,
                    src_id=runner.entity_id,
                    rel_type=RelationType.RUNS,
                    dst_id=parent_proc.entity_id,
                    context_key="runs",
                    rule_id="ocsf_host_runs_process",
                    role="HOST_PROCESS_CONTEXT",
                )
            )
        if runner is not None and actor_proc is not None:
            out.append(
                self._rel(
                    event=event,
                    src_id=runner.entity_id,
                    rel_type=RelationType.RUNS,
                    dst_id=actor_proc.entity_id,
                    context_key="runs",
                    rule_id="ocsf_host_runs_process",
                    role="HOST_PROCESS_CONTEXT",
                )
            )

        # Process Activity (1007): Parent -> Child SPAWNS
        if (
            event.class_uid == int(OcsfClassUid.PROCESS_ACTIVITY)
            and event.activity_id == 1
            and parent_proc is not None
            and actor_proc is not None
        ):
            out.append(
                self._rel(
                    event=event,
                    src_id=parent_proc.entity_id,
                    rel_type=RelationType.SPAWNS,
                    dst_id=actor_proc.entity_id,
                    context_key="spawns",
                    rule_id="ocsf_1007_process_spawn",
                    role="PROCESS_CREATE",
                    basis={
                        "parent_guid": parent_proc.attributes.get("process_guid"),
                        "child_guid": actor_proc.attributes.get("process_guid"),
                    },
                )
            )

        # File Activity (1001): Process -> File READS / WRITES
        target_file = roles.get("target_file")
        if event.class_uid == int(OcsfClassUid.FILE_ACTIVITY) and actor_proc and target_file:
            rtype = RelationType.READS if event.activity_id == 2 else RelationType.WRITES
            out.append(
                self._rel(
                    event=event,
                    src_id=actor_proc.entity_id,
                    rel_type=rtype,
                    dst_id=target_file.entity_id,
                    context_key="file_io",
                    rule_id="ocsf_1001_file_io",
                    role="ENDPOINT_FILE_IO",
                    basis={"file_path": target_file.display_label},
                )
            )

        # Network / HTTP Activity (4001 / 4002): CONNECTS_TO
        dst_ep = roles.get("dst_endpoint")
        if (
            event.class_uid in (int(OcsfClassUid.NETWORK_ACTIVITY), int(OcsfClassUid.HTTP_ACTIVITY))
            and dst_ep is not None
        ):
            ft = self._extract_five_tuple(p)
            ctx_key = self._format_tuple_key(ft)
            src_host = roles.get("src_host")
            src_ep = roles.get("src_endpoint")

            if actor_proc is not None:
                src_id = actor_proc.entity_id
                ev_role = "ENDPOINT_SOCKET"
                rule_id = "ocsf_4001_endpoint_connect"
            elif src_host is not None:
                src_id = src_host.entity_id
                ev_role = "NETWORK_SENSOR_FLOW"
                rule_id = "ocsf_4001_host_flow"
            elif src_ep is not None:
                src_id = src_ep.entity_id
                ev_role = "UNATTRIBUTED_NETWORK_FLOW"
                rule_id = "ocsf_4001_raw_flow"
            else:
                src_id = None
                ev_role = ""
                rule_id = ""

            if src_id is not None:
                out.append(
                    CandidateRelation(
                        tenant_scope=event.tenant_scope,
                        src_entity_id=src_id,
                        relation_type=RelationType.CONNECTS_TO,
                        dst_entity_id=dst_ep.entity_id,
                        certainty=Certainty.DETERMINISTIC,
                        context_key=ctx_key,
                        correlation_rule_id=rule_id,
                        observed_at=event.event_time,
                        event_id=event.event_id,
                        raw_event_id=event.raw_event_id,
                        evidence_role=ev_role,
                        correlation_basis={
                            "five_tuple": ctx_key,
                            "source_id": event.source_id,
                        },
                        five_tuple=ft,
                    )
                )

        # DNS Activity (4003): RESOLVES
        if event.class_uid == int(OcsfClassUid.DNS_ACTIVITY):
            qname = (
                str(p.get("query", {}).get("hostname") or "unknown")
                if isinstance(p.get("query"), dict)
                else "unknown"
            )
            dns_src = actor_proc or roles.get("src_host") or host or roles.get("src_endpoint")
            if dns_src is not None:
                for role_key, ent in roles.items():
                    if role_key.startswith("dns_answer_"):
                        out.append(
                            self._rel(
                                event=event,
                                src_id=dns_src.entity_id,
                                rel_type=RelationType.RESOLVES,
                                dst_id=ent.entity_id,
                                context_key=f"dns:{qname.lower()}->{ent.display_label}",
                                rule_id="ocsf_4003_dns_resolution",
                                role="DNS_ANSWER",
                                basis={"query": qname, "resolved_ip": ent.display_label},
                            )
                        )

        # Authentication (3002): AUTHENTICATES_TO
        if event.class_uid == int(OcsfClassUid.AUTHENTICATION):
            subj = roles.get("user") or actor_proc
            auth_target = roles.get("service") or host
            if subj is not None and auth_target is not None:
                out.append(
                    self._rel(
                        event=event,
                        src_id=subj.entity_id,
                        rel_type=RelationType.AUTHENTICATES_TO,
                        dst_id=auth_target.entity_id,
                        context_key="auth",
                        rule_id="ocsf_3002_authentication",
                        role="AUTH_EVENT",
                        basis={"logon_type_id": p.get("logon_type_id")},
                    )
                )

        # Application Activity (6001 / 6002 / 6003): ACCESSES / RUNS
        if event.class_uid in (
            int(OcsfClassUid.WEB_RESOURCES_ACTIVITY),
            int(OcsfClassUid.API_ACTIVITY),
        ):
            subj = roles.get("user") or actor_proc or roles.get("src_endpoint")
            res_target = roles.get("service") or target_file or host
            if subj is not None and res_target is not None:
                out.append(
                    self._rel(
                        event=event,
                        src_id=subj.entity_id,
                        rel_type=RelationType.ACCESSES,
                        dst_id=res_target.entity_id,
                        context_key="app_access",
                        rule_id=f"ocsf_{event.class_uid}_access",
                        role="APP_AUDIT",
                    )
                )
        elif event.class_uid == int(OcsfClassUid.APPLICATION_LIFECYCLE):
            svc = roles.get("service")
            if host is not None and svc is not None:
                out.append(
                    self._rel(
                        event=event,
                        src_id=host.entity_id,
                        rel_type=RelationType.RUNS,
                        dst_id=svc.entity_id,
                        context_key="service_lifecycle",
                        rule_id="ocsf_6002_service_runs",
                        role="APP_LIFECYCLE",
                    )
                )

        return out

    @staticmethod
    def _rel(
        event: NormalizedEvent,
        src_id: Any,
        rel_type: RelationType,
        dst_id: Any,
        context_key: str,
        rule_id: str,
        role: str,
        basis: dict[str, Any] | None = None,
    ) -> CandidateRelation:
        return CandidateRelation(
            tenant_scope=event.tenant_scope,
            src_entity_id=src_id,
            relation_type=rel_type,
            dst_entity_id=dst_id,
            certainty=Certainty.DETERMINISTIC,
            context_key=context_key,
            correlation_rule_id=rule_id,
            observed_at=event.event_time,
            event_id=event.event_id,
            raw_event_id=event.raw_event_id,
            evidence_role=role,
            correlation_basis=basis or {},
        )

    @staticmethod
    def _extract_five_tuple(payload: dict[str, Any]) -> FiveTuple | None:
        s_raw = payload.get("src_endpoint")
        d_raw = payload.get("dst_endpoint")
        c_raw = payload.get("connection_info")
        src_ep: dict[str, Any] = s_raw if isinstance(s_raw, dict) else {}
        dst_ep: dict[str, Any] = d_raw if isinstance(d_raw, dict) else {}
        conn: dict[str, Any] = c_raw if isinstance(c_raw, dict) else {}
        sip = src_ep.get("ip")
        dip = dst_ep.get("ip")
        if not sip or not dip:
            return None
        sport = int(src_ep["port"]) if src_ep.get("port") is not None else None
        dport = int(dst_ep["port"]) if dst_ep.get("port") is not None else None
        proto = str(conn.get("protocol_name") or "ip").lower()
        return FiveTuple(
            src_ip=str(sip),
            src_port=sport,
            dst_ip=str(dip),
            dst_port=dport,
            protocol=proto,
        )

    @staticmethod
    def _format_tuple_key(ft: FiveTuple | None) -> str:
        if ft is None:
            return "flow:unknown"
        sp = str(ft.src_port) if ft.src_port is not None else "*"
        dp = str(ft.dst_port) if ft.dst_port is not None else "*"
        return f"{ft.src_ip}:{sp}->{ft.dst_ip}:{dp}/{ft.protocol}"
