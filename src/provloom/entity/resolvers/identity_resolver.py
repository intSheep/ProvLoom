from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from provloom.domain.entity_models import (
    CandidateKey,
    Entity,
    EntityIdentifier,
    EntityMergeAudit,
    EntityObservation,
    EntityResolutionResult,
)
from provloom.domain.enums import EntityType, ResolutionState
from provloom.domain.ocsf_models import NormalizedEvent
from provloom.entity.interfaces import IdentityResolver
from provloom.observability.interfaces import PipelineTelemetry
from provloom.storage.interfaces import UnitOfWork

_GLOBAL_NAMESPACES = frozenset(
    {"asset_id", "fqdn", "container_id", "user_sid", "domain_user", "endpoint"}
)


class ScopedIdentityResolver(IdentityResolver):
    def __init__(self, uow: UnitOfWork, telemetry: PipelineTelemetry) -> None:
        self._uow = uow
        self._telemetry = telemetry

    def resolve(
        self,
        event: NormalizedEvent,
        observations: Sequence[EntityObservation],
    ) -> EntityResolutionResult:
        resolved_by_role: dict[str, Entity] = {}
        merges: list[EntityMergeAudit] = []

        for obs in observations:
            ent, obs_merges = self._resolve_single(event, obs, resolved_by_role)
            resolved_by_role[obs.role] = ent
            merges.extend(obs_merges)

        # Resolve host from active non-NAT IP lease when network sensor logs lack hostname/device.
        if "host" not in resolved_by_role and "src_endpoint" in resolved_by_role:
            src_ip = resolved_by_role["src_endpoint"].attributes.get("ip")
            if isinstance(src_ip, str):
                leased_host = self._uow.entities.find_host_by_ip(
                    event.tenant_scope, src_ip, event.event_time
                )
                if leased_host is not None and not leased_host.attributes.get(
                    "is_nat_shared", False
                ):
                    resolved_by_role["src_host"] = leased_host

        return EntityResolutionResult(by_role=resolved_by_role, merges=tuple(merges))

    def _resolve_single(
        self,
        event: NormalizedEvent,
        obs: EntityObservation,
        resolved_by_role: dict[str, Entity],
    ) -> tuple[Entity, list[EntityMergeAudit]]:
        merges: list[EntityMergeAudit] = []
        scope_entity = resolved_by_role.get("host")
        usable_scope_id: UUID | None = (
            scope_entity.entity_id
            if scope_entity is not None
            and scope_entity.resolution_state != ResolutionState.PROVISIONAL
            else None
        )

        is_launch = bool(obs.attributes.get("is_launch", False))
        is_term = bool(obs.attributes.get("is_terminate", False))

        # On process launch, close any prior active PID window on the same host before matching PID.
        if obs.entity_type == EntityType.PROCESS and is_launch and usable_scope_id is not None:
            for ck in obs.candidate_keys:
                if ck.namespace == "host_pid":
                    self._uow.entities.close_active_identifiers(
                        tenant_scope=event.tenant_scope,
                        id_namespace="host_pid",
                        id_value=ck.value,
                        scope_entity_id=usable_scope_id,
                        valid_to=event.event_time,
                    )

        # Collect authoritative matches; drop scoped keys if host scope is unknown/provisional.
        valid_auth_keys: list[tuple[CandidateKey, UUID | None]] = []
        matched_entities: list[tuple[CandidateKey, Entity]] = []

        for ck in obs.candidate_keys:
            if not ck.is_authoritative:
                continue
            scope_id: UUID | None = None
            if ck.scope_role is not None:
                if usable_scope_id is None:
                    continue
                scope_id = usable_scope_id

            # Without ProcessGuid or launch window, bare PID cannot invent a resolved entity.
            has_guid = any(k.namespace == "process_guid" for k in obs.candidate_keys)
            if (
                obs.entity_type == EntityType.PROCESS
                and ck.namespace == "host_pid"
                and not has_guid
                and not is_launch
            ):
                found_pid = self._uow.entities.find_by_identifier(
                    tenant_scope=event.tenant_scope,
                    entity_type=obs.entity_type,
                    id_namespace=ck.namespace,
                    id_value=ck.value,
                    scope_entity_id=scope_id,
                    at_time=obs.observed_at,
                )
                if found_pid is not None and self._image_compatible(found_pid, obs):
                    valid_auth_keys.append((ck, scope_id))
                    matched_entities.append((ck, found_pid))
                continue

            valid_auth_keys.append((ck, scope_id))
            found = self._uow.entities.find_by_identifier(
                tenant_scope=event.tenant_scope,
                entity_type=obs.entity_type,
                id_namespace=ck.namespace,
                id_value=ck.value,
                scope_entity_id=scope_id,
                at_time=obs.observed_at,
            )
            if found is not None:
                matched_entities.append((ck, found))

        if matched_entities:
            primary_key, survivor = matched_entities[0]
            # Deterministically merge distinct entities bridged by multiple authoritative keys.
            for bridge_key, other in matched_entities[1:]:
                if other.entity_id != survivor.entity_id:
                    audit = EntityMergeAudit(
                        merge_id=uuid4(),
                        tenant_scope=event.tenant_scope,
                        source_entity_id=other.entity_id,
                        target_entity_id=survivor.entity_id,
                        merge_rule_id=f"authoritative_bridge:{primary_key.namespace}+{bridge_key.namespace}",
                        match_basis={
                            primary_key.namespace: primary_key.value,
                            bridge_key.namespace: bridge_key.value,
                        },
                        evidence_event_ids=(event.event_id,),
                        merged_at=event.event_time,
                    )
                    self._uow.entities.merge_entities(audit)
                    self._telemetry.record_entity_merge(obs.entity_type, audit.merge_rule_id)
                    merges.append(audit)
                    merged_attrs = {**other.attributes, **survivor.attributes}
                    survivor = replace(survivor, attributes=merged_attrs)

            new_state = self._target_state(valid_auth_keys, survivor.resolution_state)
            merged_attrs = {
                **survivor.attributes,
                **{
                    k: v
                    for k, v in obs.attributes.items()
                    if v is not None and k not in {"is_launch", "is_terminate"}
                },
            }
            vf = survivor.valid_from or obs.lifecycle_start
            vt = obs.lifecycle_end or survivor.valid_to
            label = (
                obs.display_label
                if len(obs.display_label) > len(survivor.display_label)
                else survivor.display_label
            )
            survivor = replace(
                survivor,
                resolution_state=new_state,
                display_label=label,
                valid_from=vf,
                valid_to=vt,
                attributes=merged_attrs,
            )
            self._uow.entities.save_entity(survivor)
            target_entity = survivor
        else:
            state = self._target_state(valid_auth_keys, ResolutionState.PROVISIONAL)
            canonical_key: str | None = None
            if valid_auth_keys:
                k0, s0 = valid_auth_keys[0]
                scope_part = str(s0) if s0 else "global"
                time_part = (
                    obs.lifecycle_start.isoformat()
                    if k0.namespace == "host_pid" and obs.lifecycle_start is not None
                    else "static"
                )
                canonical_key = f"{k0.namespace}:{scope_part}:{k0.value}:{time_part}"
                ent_id = uuid5(
                    NAMESPACE_URL,
                    f"provloom:entity:{event.tenant_scope}:{obs.entity_type.value}:{canonical_key}",
                )
            else:
                ent_id = uuid5(
                    NAMESPACE_URL,
                    f"provloom:provisional:{event.raw_event_id}:{obs.role}",
                )

            clean_attrs = {
                k: v
                for k, v in obs.attributes.items()
                if v is not None and k not in {"is_launch", "is_terminate"}
            }
            target_entity = Entity(
                entity_id=ent_id,
                tenant_scope=event.tenant_scope,
                entity_type=obs.entity_type,
                resolution_state=state,
                display_label=obs.display_label,
                canonical_key=canonical_key,
                valid_from=obs.lifecycle_start,
                valid_to=obs.lifecycle_end,
                attributes=clean_attrs,
            )
            self._uow.entities.save_entity(target_entity)

        # Persist authoritative and searchable non-authoritative identifiers.
        auth_lookup = {ck: sid for ck, sid in valid_auth_keys}
        for ck in obs.candidate_keys:
            is_auth = ck in auth_lookup
            if ck.is_authoritative and not is_auth:
                continue
            sid = auth_lookup.get(ck)
            vf = obs.lifecycle_start if ck.namespace in {"host_pid", "host_ip_lease"} else None
            vt = obs.lifecycle_end if ck.namespace in {"host_pid", "host_ip_lease"} else None
            self._uow.entities.add_identifier(
                EntityIdentifier(
                    identifier_id=uuid4(),
                    entity_id=target_entity.entity_id,
                    tenant_scope=event.tenant_scope,
                    id_namespace=ck.namespace,
                    id_value=ck.value,
                    is_authoritative=is_auth,
                    first_seen_event_id=event.event_id,
                    scope_entity_id=sid,
                    valid_from=vf,
                    valid_to=vt,
                )
            )

        if obs.entity_type == EntityType.PROCESS and is_term and usable_scope_id is not None:
            for ck in obs.candidate_keys:
                if ck.namespace == "host_pid":
                    self._uow.entities.close_active_identifiers(
                        tenant_scope=event.tenant_scope,
                        id_namespace="host_pid",
                        id_value=ck.value,
                        scope_entity_id=usable_scope_id,
                        valid_to=event.event_time,
                    )

        return target_entity, merges

    @staticmethod
    def _image_compatible(existing: Entity, obs: EntityObservation) -> bool:
        ex_img = existing.attributes.get("image")
        ob_img = obs.attributes.get("image")
        if isinstance(ex_img, str) and isinstance(ob_img, str) and ex_img and ob_img:
            ex_base = ex_img.replace("/", "\\").rsplit("\\", 1)[-1].lower()
            ob_base = ob_img.replace("/", "\\").rsplit("\\", 1)[-1].lower()
            return ex_base == ob_base
        return True

    @staticmethod
    def _target_state(
        valid_auth_keys: Sequence[tuple[CandidateKey, UUID | None]],
        fallback: ResolutionState,
    ) -> ResolutionState:
        if not valid_auth_keys:
            return fallback
        if any(
            ck.namespace in _GLOBAL_NAMESPACES or ck.namespace == "process_guid"
            for ck, _ in valid_auth_keys
        ):
            return ResolutionState.RESOLVED
        return ResolutionState.SCOPED_TEMPORAL
