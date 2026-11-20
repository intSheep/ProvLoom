from __future__ import annotations

from collections.abc import Sequence

from sigma.pipelines.ocsf.ocsf import ocsf_pipeline as upstream_ocsf_pipeline
from sigma.processing.conditions import (
    LogsourceCondition,
    RuleContainsDetectionItemCondition,
    RuleContainsFieldCondition,
    RuleProcessingCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    AddConditionTransformation,
    FieldMappingTransformation,
)
from sigma.rule import SigmaRule

from provloom.normalization.interfaces import MappingSpecSummary

# Canonical OCSF v1.3.0 fields supported by the SQL Detection Backend.
KNOWN_OCSF_V13_FIELDS: frozenset[str] = frozenset(
    {
        # Top-level / envelope attributes
        "class_uid",
        "category_uid",
        "activity_id",
        "type_uid",
        "source_id",
        "ocsf_version",
        "original_event_uid",
        "metadata.original_uid",
        "metadata.version",
        "metadata.event_code",
        "metadata.log_name",
        "metadata.log_provider",
        "unmapped.EventID",
        # Device / Host / Asset (1007, 1001, 4001, 5001, 600x)
        "device.uid",
        "device.hostname",
        "device.ip",
        "device.os.name",
        "device.is_nat_shared",
        "container.uid",
        "container.runtime",
        # Actor & Process (1007, 1001, 4001, 4003)
        "actor.user.name",
        "actor.user.domain",
        "actor.user.uid",
        "actor.process.uid",
        "actor.process.pid",
        "actor.process.cmd_line",
        "actor.process.file.path",
        "process.uid",
        "process.pid",
        "process.cmd_line",
        "process.working_directory",
        "process.session.uid",
        "process.file.path",
        "process.file.name",
        "process.file.desc",
        "process.file.internal_name",
        "process.file.hashes.sha256",
        "process.parent_process.uid",
        "process.parent_process.pid",
        "process.parent_process.cmd_line",
        "process.parent_process.file.path",
        "process.parent_process.name",
        # File System Activity (1001)
        "file.path",
        "file.name",
        "file.created_time",
        "file.hashes.sha256",
        "file_result.file.path",
        "file_result.file.name",
        # Network & Firewall (4001)
        "src_endpoint.ip",
        "src_endpoint.port",
        "src_endpoint.hostname",
        "src_endpoint.name",
        "dst_endpoint.ip",
        "dst_endpoint.port",
        "dst_endpoint.hostname",
        "connection_info.protocol_name",
        "disposition",
        "traffic.bytes_in",
        "traffic.bytes_out",
        # DNS Activity (4003)
        "query.hostname",
        "query.type",
        "answers",
        "rcode",
        # Authentication / IAM (3002)
        "user.uid",
        "user.name",
        "user.domain",
        "logon_type_id",
        # Service & Application Activity (6001, 6002, 6003)
        "service.name",
        "service.port",
        "app.name",
        "api.operation",
        "web_resources.path",
        # PowerShell / Script / Registry / Service extensions
        "script.script_content",
        "script.file.path",
        "reg_key.path",
        "win_service.name",
        "win_service.cmd_line",
    }
)

ARRAY_OCSF_FIELDS: frozenset[str] = frozenset({"answers"})

# Default field coverage from ProvLoom's built-in OCSF v1.3.0 YAML mappings by class_uid.
DEFAULT_PROVLOOM_COVERED_FIELDS: dict[int, frozenset[str]] = {
    1001: frozenset(
        {
            "class_uid",
            "category_uid",
            "activity_id",
            "type_uid",
            "metadata.original_uid",
            "device.hostname",
            "actor.user.name",
            "actor.process.uid",
            "actor.process.pid",
            "actor.process.file.path",
            "file.path",
            "file.hashes.sha256",
            "unmapped.EventID",
        }
    ),
    1007: frozenset(
        {
            "class_uid",
            "category_uid",
            "activity_id",
            "type_uid",
            "metadata.original_uid",
            "device.hostname",
            "actor.user.name",
            "process.uid",
            "process.pid",
            "process.cmd_line",
            "process.file.path",
            "process.parent_process.uid",
            "process.parent_process.pid",
            "process.parent_process.cmd_line",
            "process.parent_process.file.path",
            "unmapped.EventID",
        }
    ),
    3002: frozenset(
        {
            "class_uid",
            "category_uid",
            "activity_id",
            "type_uid",
            "metadata.original_uid",
            "dst_endpoint.hostname",
            "user.uid",
            "user.name",
            "user.domain",
            "src_endpoint.ip",
            "logon_type_id",
            "service.name",
            "unmapped.EventID",
        }
    ),
    4001: frozenset(
        {
            "class_uid",
            "category_uid",
            "activity_id",
            "type_uid",
            "metadata.original_uid",
            "device.hostname",
            "actor.user.name",
            "actor.process.uid",
            "actor.process.pid",
            "actor.process.file.path",
            "src_endpoint.ip",
            "src_endpoint.port",
            "dst_endpoint.ip",
            "dst_endpoint.port",
            "connection_info.protocol_name",
            "disposition",
            "traffic.bytes_out",
            "traffic.bytes_in",
            "unmapped.EventID",
        }
    ),
    4003: frozenset(
        {
            "class_uid",
            "category_uid",
            "activity_id",
            "type_uid",
            "metadata.original_uid",
            "device.hostname",
            "actor.process.uid",
            "actor.process.pid",
            "actor.process.file.path",
            "src_endpoint.ip",
            "src_endpoint.port",
            "dst_endpoint.ip",
            "dst_endpoint.port",
            "connection_info.protocol_name",
            "query.hostname",
            "answers",
            "rcode",
            "unmapped.EventID",
        }
    ),
    5001: frozenset(
        {
            "class_uid",
            "category_uid",
            "activity_id",
            "type_uid",
            "metadata.original_uid",
            "device.uid",
            "device.hostname",
            "device.ip",
            "device.os.name",
            "device.is_nat_shared",
            "container.uid",
            "container.runtime",
            "service.name",
            "service.port",
        }
    ),
    6001: frozenset(
        {
            "class_uid",
            "category_uid",
            "activity_id",
            "type_uid",
            "metadata.original_uid",
            "device.hostname",
            "actor.user.name",
            "actor.user.domain",
            "service.name",
            "service.port",
            "web_resources.path",
            "src_endpoint.ip",
        }
    ),
    6002: frozenset(
        {
            "class_uid",
            "category_uid",
            "activity_id",
            "type_uid",
            "metadata.original_uid",
            "device.hostname",
            "app.name",
            "service.name",
            "service.port",
        }
    ),
    6003: frozenset(
        {
            "class_uid",
            "category_uid",
            "activity_id",
            "type_uid",
            "metadata.original_uid",
            "device.hostname",
            "actor.user.name",
            "actor.user.domain",
            "service.name",
            "service.port",
            "api.operation",
            "src_endpoint.ip",
        }
    ),
}

_CATEGORY_TO_OCSF_CONDITION: dict[str, dict[str, int]] = {
    "process_creation": {"class_uid": 1007, "activity_id": 1},
    "process_termination": {"class_uid": 1007, "activity_id": 2},
    "process_access": {"class_uid": 1007, "activity_id": 99},
    "file_event": {"class_uid": 1001, "activity_id": 1},
    "file_access": {"class_uid": 1001, "activity_id": 2},
    "file_change": {"class_uid": 1001},
    "file_delete": {"class_uid": 1001, "activity_id": 4},
    "network_connection": {"class_uid": 4001},
    "firewall": {"class_uid": 4001},
    "dns": {"class_uid": 4003},
    "dns_query": {"class_uid": 4003},
    "authentication": {"class_uid": 3002},
    "webserver": {"class_uid": 6001},
    "web_access": {"class_uid": 6001},
    "application": {"class_uid": 6002},
    "api_activity": {"class_uid": 6003},
}


def _make_fmap(mapping: dict[str, str]) -> dict[str | None, str | list[str]]:
    return {k: v for k, v in mapping.items()}


def build_provloom_ocsf_pipeline() -> ProcessingPipeline:
    """Composes ProvLoom OCSF v1.3.0 canonical field mappings with pySigma-pipeline-ocsf."""
    v13_items: list[ProcessingItem] = [
        ProcessingItem(
            identifier=f"provloom_ocsf_v13_cat_{category}_{field}",
            transformation=AddConditionTransformation({field: val}),
            rule_conditions=[LogsourceCondition(category=category)],
        )
        for category, cond_map in _CATEGORY_TO_OCSF_CONDITION.items()
        for field, val in sorted(cond_map.items())
    ]

    v13_items.append(
        ProcessingItem(
            identifier="provloom_ocsf_v13_win_security_auth_class",
            transformation=AddConditionTransformation({"class_uid": 3002}),
            rule_conditions=[
                LogsourceCondition(product="windows"),
                LogsourceCondition(service="security"),
                RuleContainsFieldCondition(field="EventID"),
                RuleContainsDetectionItemCondition(field="EventID", value=4624),
            ],
        )
    )
    v13_items.append(
        ProcessingItem(
            identifier="provloom_ocsf_v13_win_security_auth_fail_class",
            transformation=AddConditionTransformation({"class_uid": 3002}),
            rule_conditions=[
                LogsourceCondition(product="windows"),
                LogsourceCondition(service="security"),
                RuleContainsFieldCondition(field="EventID"),
                RuleContainsDetectionItemCondition(field="EventID", value=4625),
            ],
        )
    )

    category_field_maps: list[tuple[str, list[RuleProcessingCondition], dict[str, str]]] = [
        (
            "process_creation",
            [LogsourceCondition(category="process_creation")],
            {
                "Image": "process.file.path",
                "CommandLine": "process.cmd_line",
                "ProcessId": "process.pid",
                "ProcessGuid": "process.uid",
                "ParentImage": "process.parent_process.file.path",
                "ParentCommandLine": "process.parent_process.cmd_line",
                "ParentProcessId": "process.parent_process.pid",
                "ParentProcessGuid": "process.parent_process.uid",
                "User": "actor.user.name",
                "Computer": "device.hostname",
                "Hostname": "device.hostname",
                "CurrentDirectory": "process.working_directory",
                "OriginalFileName": "process.file.internal_name",
                "sha256": "process.file.hashes.sha256",
                "EventID": "unmapped.EventID",
            },
        ),
        (
            "process_termination",
            [LogsourceCondition(category="process_termination")],
            {
                "Image": "process.file.path",
                "ProcessId": "process.pid",
                "ProcessGuid": "process.uid",
                "User": "actor.user.name",
                "Computer": "device.hostname",
                "EventID": "unmapped.EventID",
            },
        ),
        (
            "process_access",
            [LogsourceCondition(category="process_access")],
            {
                "SourceImage": "actor.process.file.path",
                "SourceProcessGUID": "actor.process.uid",
                "SourceProcessId": "actor.process.pid",
                "TargetImage": "process.file.path",
                "TargetProcessGUID": "process.uid",
                "TargetProcessId": "process.pid",
                "SourceUser": "actor.user.name",
                "Computer": "device.hostname",
                "EventID": "unmapped.EventID",
            },
        ),
    ]

    for ident, conds, fmap in category_field_maps:
        v13_items.append(
            ProcessingItem(
                identifier=f"provloom_ocsf_v13_fields_{ident}",
                transformation=FieldMappingTransformation(_make_fmap(fmap)),
                rule_conditions=conds,
            )
        )

    file_fmap = {
        "Image": "actor.process.file.path",
        "ProcessGuid": "actor.process.uid",
        "ProcessId": "actor.process.pid",
        "User": "actor.user.name",
        "Computer": "device.hostname",
        "TargetFilename": "file.path",
        "FileName": "file.path",
        "sha256": "file.hashes.sha256",
        "EventID": "unmapped.EventID",
    }
    for file_cat in ("file_event", "file_access", "file_change", "file_delete"):
        v13_items.append(
            ProcessingItem(
                identifier=f"provloom_ocsf_v13_fields_{file_cat}",
                transformation=FieldMappingTransformation(_make_fmap(file_fmap)),
                rule_conditions=[LogsourceCondition(category=file_cat)],
            )
        )

    for net_cat in ("network_connection", "firewall"):
        v13_items.append(
            ProcessingItem(
                identifier=f"provloom_ocsf_v13_fields_{net_cat}",
                transformation=FieldMappingTransformation(
                    _make_fmap(
                        {
                            "Image": "actor.process.file.path",
                            "ProcessGuid": "actor.process.uid",
                            "ProcessId": "actor.process.pid",
                            "User": "actor.user.name",
                            "Computer": "device.hostname",
                            "SourceIp": "src_endpoint.ip",
                            "SourcePort": "src_endpoint.port",
                            "SourceHostname": "src_endpoint.hostname",
                            "DestinationIp": "dst_endpoint.ip",
                            "DestinationPort": "dst_endpoint.port",
                            "DestinationHostname": "dst_endpoint.hostname",
                            "Protocol": "connection_info.protocol_name",
                            "src_ip": "src_endpoint.ip",
                            "src_port": "src_endpoint.port",
                            "dst_ip": "dst_endpoint.ip",
                            "dst_port": "dst_endpoint.port",
                            "protocol": "connection_info.protocol_name",
                            "action": "disposition",
                            "bytes_sent": "traffic.bytes_out",
                            "bytes_received": "traffic.bytes_in",
                            "EventID": "unmapped.EventID",
                        }
                    )
                ),
                rule_conditions=[LogsourceCondition(category=net_cat)],
            )
        )

    for dns_cat in ("dns", "dns_query"):
        v13_items.append(
            ProcessingItem(
                identifier=f"provloom_ocsf_v13_fields_{dns_cat}",
                transformation=FieldMappingTransformation(
                    _make_fmap(
                        {
                            "Image": "actor.process.file.path",
                            "ProcessGuid": "actor.process.uid",
                            "ProcessId": "actor.process.pid",
                            "Computer": "device.hostname",
                            "QueryName": "query.hostname",
                            "query": "query.hostname",
                            "QueryResults": "answers",
                            "answers": "answers",
                            "answer": "answers",
                            "rcode_name": "rcode",
                            "record_type": "query.type",
                            "SourceIp": "src_endpoint.ip",
                            "DestinationIp": "dst_endpoint.ip",
                            "EventID": "unmapped.EventID",
                        }
                    )
                ),
                rule_conditions=[LogsourceCondition(category=dns_cat)],
            )
        )

    auth_map: dict[str | None, str | list[str]] = {
        "TargetUserName": "user.name",
        "TargetDomainName": "user.domain",
        "TargetUserSid": "user.uid",
        "User": "user.name",
        "IpAddress": "src_endpoint.ip",
        "SourceIp": "src_endpoint.ip",
        "WorkstationName": "src_endpoint.hostname",
        "Computer": "dst_endpoint.hostname",
        "LogonType": "logon_type_id",
        "ServiceName": "service.name",
        "EventID": "unmapped.EventID",
    }
    v13_items.append(
        ProcessingItem(
            identifier="provloom_ocsf_v13_fields_authentication",
            transformation=FieldMappingTransformation(auth_map),
            rule_conditions=[LogsourceCondition(category="authentication")],
        )
    )
    v13_items.append(
        ProcessingItem(
            identifier="provloom_ocsf_v13_fields_windows_security",
            transformation=FieldMappingTransformation(auth_map),
            rule_conditions=[
                LogsourceCondition(product="windows"),
                LogsourceCondition(service="security"),
            ],
        )
    )

    for web_cat in ("webserver", "web_access"):
        v13_items.append(
            ProcessingItem(
                identifier=f"provloom_ocsf_v13_fields_{web_cat}",
                transformation=FieldMappingTransformation(
                    _make_fmap(
                        {
                            "cs-uri-stem": "web_resources.path",
                            "cs-uri": "web_resources.path",
                            "resource_path": "web_resources.path",
                            "c-ip": "src_endpoint.ip",
                            "src_ip": "src_endpoint.ip",
                            "username": "actor.user.name",
                            "hostname": "device.hostname",
                            "service_name": "service.name",
                        }
                    )
                ),
                rule_conditions=[LogsourceCondition(category=web_cat)],
            )
        )

    for app_cat in ("application", "api_activity"):
        v13_items.append(
            ProcessingItem(
                identifier=f"provloom_ocsf_v13_fields_{app_cat}",
                transformation=FieldMappingTransformation(
                    _make_fmap(
                        {
                            "operation": "api.operation",
                            "service_name": "service.name",
                            "username": "actor.user.name",
                            "domain": "actor.user.domain",
                            "hostname": "device.hostname",
                            "src_ip": "src_endpoint.ip",
                            "EventID": "unmapped.EventID",
                        }
                    )
                ),
                rule_conditions=[LogsourceCondition(category=app_cat)],
            )
        )

    # Layer sanitized upstream pySigma-pipeline-ocsf items for additional categories.
    upstream: ProcessingPipeline = upstream_ocsf_pipeline()
    upstream._clear_pipeline()
    handled_categories = set(_CATEGORY_TO_OCSF_CONDITION.keys())
    sanitized_upstream_items: list[ProcessingItem] = []
    for item in upstream.items:
        ident = item.identifier or ""
        if isinstance(item.transformation, AddConditionTransformation):
            cat_conds = [
                c.category
                for c in item.rule_conditions
                if isinstance(c, LogsourceCondition) and c.category is not None
            ]
            if any(c in handled_categories for c in cat_conds):
                continue
            if ident.startswith("ocsf_windows_security_"):
                continue
            sanitized_upstream_items.append(item)
        elif isinstance(item.transformation, FieldMappingTransformation):
            cleaned_map: dict[str | None, str | list[str]] = {
                src: dst
                for src, dst in item.transformation.mapping.items()
                if isinstance(dst, str) and src != dst and not dst.startswith("unmapped.")
            }
            if cleaned_map:
                r_conds = (
                    list(item.rule_conditions.values())
                    if isinstance(item.rule_conditions, dict)
                    else list(item.rule_conditions)
                )
                d_conds = (
                    list(item.detection_item_conditions.values())
                    if isinstance(item.detection_item_conditions, dict)
                    else list(item.detection_item_conditions)
                )
                f_conds = (
                    list(item.field_name_conditions.values())
                    if isinstance(item.field_name_conditions, dict)
                    else list(item.field_name_conditions)
                )
                sanitized_upstream_items.append(
                    ProcessingItem(
                        identifier=ident,
                        transformation=FieldMappingTransformation(cleaned_map),
                        rule_conditions=r_conds,
                        detection_item_conditions=d_conds,
                        field_name_conditions=f_conds,
                    )
                )

    return ProcessingPipeline(
        name="ProvLoom OCSF v1.3.0 Pipeline",
        priority=10,
        items=v13_items + sanitized_upstream_items,
    )


def apply_ocsf_pipeline(rule: SigmaRule) -> tuple[SigmaRule, dict[str, str]]:
    pipeline = build_provloom_ocsf_pipeline()
    transformed = pipeline.apply(rule)
    assert isinstance(transformed, SigmaRule)
    resolved_mappings: dict[str, str] = {}
    for src_field, dst_set in pipeline.field_mappings.items():
        if src_field is not None and dst_set:
            resolved_mappings[src_field] = sorted(dst_set)[0]
    return transformed, resolved_mappings


def evaluate_data_coverage(
    mapped_class_uids: Sequence[int],
    referenced_fields: Sequence[str],
    mapping_specs: Sequence[MappingSpecSummary] | None = None,
) -> tuple[bool, tuple[str, ...]]:
    active_classes = (
        {s.class_uid for s in mapping_specs}
        if mapping_specs
        else set(DEFAULT_PROVLOOM_COVERED_FIELDS.keys())
    )
    uncovered: list[str] = []
    if mapped_class_uids:
        missing_classes = [c for c in mapped_class_uids if c not in active_classes]
        if missing_classes:
            uncovered.extend(f"class_uid:{c}" for c in missing_classes)

    allowed_fields: set[str] = {
        "class_uid",
        "category_uid",
        "activity_id",
        "type_uid",
        "source_id",
        "ocsf_version",
        "original_event_uid",
    }
    if mapped_class_uids:
        for cid in mapped_class_uids:
            allowed_fields |= set(DEFAULT_PROVLOOM_COVERED_FIELDS.get(cid, frozenset()))
    else:
        for cov in DEFAULT_PROVLOOM_COVERED_FIELDS.values():
            allowed_fields |= set(cov)

    for f in referenced_fields:
        if f not in allowed_fields:
            uncovered.append(f)

    deduped = tuple(dict.fromkeys(uncovered))
    return (len(deduped) == 0, deduped)
