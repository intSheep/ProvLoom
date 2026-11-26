from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, ClassVar

from sigma.conditions import (
    ConditionAND,
    ConditionItem,
    ConditionNOT,
)
from sigma.exceptions import SigmaRuleLocation
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
from sigma.processing.transformations.base import DetectionItemTransformation
from sigma.rule import SigmaRule
from sigma.rule.detection import SigmaDetection, SigmaDetectionItem, SigmaDetections
from sigma.types import SigmaExists, SigmaNull, SigmaNumber, SigmaString

from provloom.normalization.interfaces import MappingSpecSummary

# Canonical OCSF v1.4.0 scalar fields supported by the SQL Detection Backend
# (pinned to ocsf/ocsf-schema tag 1.4.0, commit 6109cc5e834c1adfee67dda6c9bcfa5e37f79012).
KNOWN_OCSF_V14_FIELDS: frozenset[str] = frozenset(
    {
        # Top-level / envelope attributes
        "class_uid",
        "category_uid",
        "activity_id",
        "type_uid",
        "severity_id",
        "source_id",
        "ocsf_version",
        "original_event_uid",
        "metadata.original_uid",
        "metadata.version",
        "metadata.event_code",
        "metadata.log_name",
        "metadata.log_provider",
        "unmapped.EventID",
        "unmapped.is_nat_shared",
        "unmapped.valid_from",
        "unmapped.valid_to",
        "unmapped.container_id",
        "unmapped.runtime",
        "unmapped.service_name",
        "unmapped.listen_port",
        # Device / Host / Container
        "device.uid",
        "device.hostname",
        "device.ip",
        "device.os.name",
        "container.uid",
        "container.runtime",
        # Actor & Process (1007, 1001, 1009, 4001, 4003)
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
        "process.file.hashes.algorithm_id",
        "process.file.hashes.algorithm",
        "process.file.hashes.value",
        "process.parent_process.uid",
        "process.parent_process.pid",
        "process.parent_process.cmd_line",
        "process.parent_process.file.path",
        "process.parent_process.name",
        # File System Activity (1001)
        "file.path",
        "file.name",
        "file.created_time",
        "file.hashes.algorithm_id",
        "file.hashes.algorithm",
        "file.hashes.value",
        # Script Activity (1009) — script_content is long_string object; text is in .value
        "script.script_content.value",
        "script.file.path",
        "script.uid",
        "script.name",
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
        # DNS Activity (4003) — answers is dns_answer[]; answer value is in .rdata
        "query.hostname",
        "query.type",
        "answers.rdata",
        "rcode",
        # Authentication / IAM (3002)
        "user.uid",
        "user.name",
        "user.domain",
        "logon_type_id",
        "service.name",
        # Application Activity (6001, 6002, 6003)
        "app.name",
        "api.operation",
        "api.service.name",
        "web_resources.url_string",
        # Windows Registry / Service extensions
        "reg_key.path",
        "win_service.name",
        "win_service.cmd_line",
    }
)

# Historical alias retained for external imports.
KNOWN_OCSF_V13_FIELDS: frozenset[str] = KNOWN_OCSF_V14_FIELDS

# OCSF object-array fields: field_path -> (array_path, leaf_attr, allow_legacy_str)
# allow_legacy_str=True on answers.rdata is a historical compatibility path for
# pre-1.4.0 string-array/scalar DNS answers before tenant replay.
OBJECT_ARRAY_OCSF_FIELDS: dict[str, tuple[tuple[str, ...], str, bool]] = {
    "answers.rdata": (("answers",), "rdata", True),
    "file.hashes.algorithm_id": (("file", "hashes"), "algorithm_id", False),
    "file.hashes.algorithm": (("file", "hashes"), "algorithm", False),
    "file.hashes.value": (("file", "hashes"), "value", False),
    "process.file.hashes.algorithm_id": (("process", "file", "hashes"), "algorithm_id", False),
    "process.file.hashes.algorithm": (("process", "file", "hashes"), "algorithm", False),
    "process.file.hashes.value": (("process", "file", "hashes"), "value", False),
    "web_resources.url_string": (("web_resources",), "url_string", False),
}

# Default field coverage from ProvLoom's built-in OCSF v1.4.0 YAML mappings by class_uid.
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
            "file.hashes.algorithm_id",
            "file.hashes.algorithm",
            "file.hashes.value",
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
            "actor.process.uid",
            "actor.process.pid",
            "actor.process.file.path",
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
    1009: frozenset(
        {
            "class_uid",
            "category_uid",
            "activity_id",
            "type_uid",
            "metadata.original_uid",
            "device.hostname",
            "actor.user.name",
            "actor.process.pid",
            "script.uid",
            "script.name",
            "script.file.path",
            "script.script_content.value",
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
            "src_endpoint.hostname",
            "src_endpoint.ip",
            "src_endpoint.port",
            "dst_endpoint.ip",
            "dst_endpoint.port",
            "connection_info.protocol_name",
            "query.hostname",
            "answers.rdata",
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
            "unmapped.is_nat_shared",
            "unmapped.valid_from",
            "unmapped.valid_to",
            "unmapped.container_id",
            "unmapped.runtime",
            "unmapped.service_name",
            "unmapped.listen_port",
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
            "web_resources.url_string",
            "src_endpoint.ip",
            "unmapped.service_name",
            "unmapped.listen_port",
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
            "unmapped.service_name",
            "unmapped.listen_port",
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
            "api.service.name",
            "api.operation",
            "src_endpoint.ip",
            "unmapped.listen_port",
        }
    ),
}

_CATEGORY_TO_OCSF_CONDITION: dict[str, dict[str, int]] = {
    "process_creation": {"class_uid": 1007, "activity_id": 1},
    "process_termination": {"class_uid": 1007, "activity_id": 2},
    "process_access": {"class_uid": 1007, "activity_id": 99},
    "ps_script": {"class_uid": 1009, "activity_id": 1},
    "ps_module": {"class_uid": 1009, "activity_id": 1},
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


_HASH_FIELD_TO_ALGO_ID: dict[str, int] = {
    "md5": 1,
    "MD5": 1,
    "sha1": 2,
    "SHA1": 2,
    "sha256": 3,
    "SHA256": 3,
    "sha512": 4,
    "SHA512": 4,
}


class _NegatableSigmaDetection(SigmaDetection):
    """SigmaDetection subclass that preserves negation for multi-item algorithm+value rewrites."""

    def __init__(
        self,
        detection_items: list[SigmaDetectionItem | SigmaDetection],
        source: SigmaRuleLocation | None = None,
        item_linking: type[ConditionAND | Any] | None = None,
        *,
        negated: bool = False,
    ) -> None:
        super().__init__(detection_items=detection_items, source=source, item_linking=item_linking)
        self.negated = negated

    def postprocess(
        self,
        detections: SigmaDetections,
        parent: SigmaDetection | SigmaDetectionItem | ConditionItem | None = None,
        source: SigmaRuleLocation | None = None,
    ) -> ConditionItem | Any | None:
        cond = super().postprocess(detections, parent, source)
        if self.negated and cond is not None:
            not_cond = ConditionNOT([cond])
            not_cond.parent = parent
            not_cond.source = self.source
            cond.parent = not_cond
            return not_cond
        return cond


@dataclass
class _ScopedHashAlgorithmTransformation(DetectionItemTransformation):
    """Expand Sigma hash fields (md5/sha1/sha256/sha512) into (algorithm_id AND value) pairs."""

    prefix: str
    _HASH_MAP: ClassVar[dict[str, int]] = _HASH_FIELD_TO_ALGO_ID

    def apply_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> SigmaDetection | SigmaDetectionItem | None:
        orig_field = detection_item.field
        if orig_field is None or orig_field not in self._HASH_MAP:
            return detection_item

        alg_id = self._HASH_MAP[orig_field]
        alg_item = SigmaDetectionItem(
            field=f"{self.prefix}.algorithm_id",
            modifiers=[],
            value=[SigmaNumber(alg_id)],
            source=detection_item.source,
            auto_modifiers=False,
        )
        vals = list(detection_item.value)
        if not vals or (len(vals) == 1 and isinstance(vals[0], SigmaNull)):
            val_item = SigmaDetectionItem(
                field=f"{self.prefix}.value",
                modifiers=[],
                value=[SigmaString("*")],
                source=detection_item.source,
                auto_modifiers=False,
            )
            negated = not bool(detection_item.negated)
        elif len(vals) == 1 and isinstance(vals[0], SigmaExists):
            val_item = SigmaDetectionItem(
                field=f"{self.prefix}.value",
                modifiers=[],
                value=[SigmaExists(True)],
                source=detection_item.source,
                auto_modifiers=False,
            )
            negated = (not bool(vals[0].exists)) ^ bool(detection_item.negated)
        else:
            val_item = SigmaDetectionItem(
                field=f"{self.prefix}.value",
                modifiers=[],
                value=vals,
                value_linking=detection_item.value_linking,
                negated=False,
                source=detection_item.source,
                auto_modifiers=False,
            )
            negated = bool(detection_item.negated)

        if self._pipeline is not None:
            self._pipeline.field_mappings.setdefault(orig_field, set()).add(f"{self.prefix}.value")

        return _NegatableSigmaDetection(
            detection_items=[alg_item, val_item],
            source=detection_item.source,
            item_linking=ConditionAND,
            negated=negated,
        )


def build_provloom_ocsf_pipeline() -> ProcessingPipeline:
    """Composes ProvLoom OCSF v1.4.0 field mappings with sanitized pySigma-pipeline-ocsf."""
    v14_items: list[ProcessingItem] = [
        ProcessingItem(
            identifier=f"provloom_ocsf_v14_cat_{category}_{field}",
            transformation=AddConditionTransformation({field: val}),
            rule_conditions=[LogsourceCondition(category=category)],
        )
        for category, cond_map in _CATEGORY_TO_OCSF_CONDITION.items()
        for field, val in sorted(cond_map.items())
    ]

    v14_items.append(
        ProcessingItem(
            identifier="provloom_ocsf_v14_win_security_auth_class",
            transformation=AddConditionTransformation({"class_uid": 3002}),
            rule_conditions=[
                LogsourceCondition(product="windows"),
                LogsourceCondition(service="security"),
                RuleContainsFieldCondition(field="EventID"),
                RuleContainsDetectionItemCondition(field="EventID", value=4624),
            ],
        )
    )
    v14_items.append(
        ProcessingItem(
            identifier="provloom_ocsf_v14_win_security_auth_fail_class",
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
                "Description": "process.file.desc",
                "LogonId": "process.session.uid",
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
        (
            "ps_script",
            [LogsourceCondition(category="ps_script")],
            {
                "ScriptBlockText": "script.script_content.value",
                "Path": "script.file.path",
                "ScriptBlockId": "script.uid",
                "Computer": "device.hostname",
                "EventID": "unmapped.EventID",
            },
        ),
        (
            "ps_module",
            [LogsourceCondition(category="ps_module")],
            {
                "Payload": "script.script_content.value",
                "Computer": "device.hostname",
                "EventID": "unmapped.EventID",
            },
        ),
    ]

    v14_items.append(
        ProcessingItem(
            identifier="provloom_ocsf_v14_hashes_process_creation",
            transformation=_ScopedHashAlgorithmTransformation(prefix="process.file.hashes"),
            rule_conditions=[LogsourceCondition(category="process_creation")],
        )
    )
    for ident, conds, fmap in category_field_maps:
        v14_items.append(
            ProcessingItem(
                identifier=f"provloom_ocsf_v14_fields_{ident}",
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
        "EventID": "unmapped.EventID",
    }
    for file_cat in ("file_event", "file_access", "file_change", "file_delete"):
        v14_items.append(
            ProcessingItem(
                identifier=f"provloom_ocsf_v14_hashes_{file_cat}",
                transformation=_ScopedHashAlgorithmTransformation(prefix="file.hashes"),
                rule_conditions=[LogsourceCondition(category=file_cat)],
            )
        )
        v14_items.append(
            ProcessingItem(
                identifier=f"provloom_ocsf_v14_fields_{file_cat}",
                transformation=FieldMappingTransformation(_make_fmap(file_fmap)),
                rule_conditions=[LogsourceCondition(category=file_cat)],
            )
        )

    for net_cat in ("network_connection", "firewall"):
        v14_items.append(
            ProcessingItem(
                identifier=f"provloom_ocsf_v14_fields_{net_cat}",
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
        v14_items.append(
            ProcessingItem(
                identifier=f"provloom_ocsf_v14_fields_{dns_cat}",
                transformation=FieldMappingTransformation(
                    _make_fmap(
                        {
                            "Image": "actor.process.file.path",
                            "ProcessGuid": "actor.process.uid",
                            "ProcessId": "actor.process.pid",
                            "Computer": "device.hostname",
                            "QueryName": "query.hostname",
                            "query": "query.hostname",
                            "QueryResults": "answers.rdata",
                            "answers": "answers.rdata",
                            "answer": "answers.rdata",
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
    v14_items.append(
        ProcessingItem(
            identifier="provloom_ocsf_v14_fields_authentication",
            transformation=FieldMappingTransformation(auth_map),
            rule_conditions=[LogsourceCondition(category="authentication")],
        )
    )
    v14_items.append(
        ProcessingItem(
            identifier="provloom_ocsf_v14_fields_windows_security",
            transformation=FieldMappingTransformation(auth_map),
            rule_conditions=[
                LogsourceCondition(product="windows"),
                LogsourceCondition(service="security"),
            ],
        )
    )

    for web_cat in ("webserver", "web_access"):
        v14_items.append(
            ProcessingItem(
                identifier=f"provloom_ocsf_v14_fields_{web_cat}",
                transformation=FieldMappingTransformation(
                    _make_fmap(
                        {
                            "cs-uri-stem": "web_resources.url_string",
                            "cs-uri": "web_resources.url_string",
                            "resource_path": "web_resources.url_string",
                            "c-ip": "src_endpoint.ip",
                            "src_ip": "src_endpoint.ip",
                            "username": "actor.user.name",
                            "hostname": "device.hostname",
                        }
                    )
                ),
                rule_conditions=[LogsourceCondition(category=web_cat)],
            )
        )

    v14_items.append(
        ProcessingItem(
            identifier="provloom_ocsf_v14_fields_application",
            transformation=FieldMappingTransformation(
                _make_fmap(
                    {
                        "service_name": "app.name",
                        "hostname": "device.hostname",
                        "EventID": "unmapped.EventID",
                    }
                )
            ),
            rule_conditions=[LogsourceCondition(category="application")],
        )
    )
    v14_items.append(
        ProcessingItem(
            identifier="provloom_ocsf_v14_fields_api_activity",
            transformation=FieldMappingTransformation(
                _make_fmap(
                    {
                        "operation": "api.operation",
                        "service_name": "api.service.name",
                        "username": "actor.user.name",
                        "domain": "actor.user.domain",
                        "hostname": "device.hostname",
                        "src_ip": "src_endpoint.ip",
                        "EventID": "unmapped.EventID",
                    }
                )
            ),
            rule_conditions=[LogsourceCondition(category="api_activity")],
        )
    )

    # Layer sanitized upstream pySigma-pipeline-ocsf items only for unhandled categories,
    # excluding upstream collisions and non-OCSF-v1.4.0 paths.
    upstream: ProcessingPipeline = upstream_ocsf_pipeline()
    upstream._clear_pipeline()
    handled_categories = set(_CATEGORY_TO_OCSF_CONDITION.keys())
    invalid_upstream_pairs: frozenset[tuple[str, str]] = frozenset(
        {
            ("Image", "reg_key.path"),
            ("Image", "file.name"),
            ("Image", "query.hostname"),
            ("ParentImage", "file.name"),
            ("ScriptBlockText", "script.script_content"),
            ("Payload", "script.script_content"),
            ("answer", "answer.rdata"),
        }
    )
    sanitized_upstream_items: list[ProcessingItem] = []
    for item in upstream.items:
        ident = item.identifier or ""
        r_conds = (
            list(item.rule_conditions.values())
            if isinstance(item.rule_conditions, dict)
            else list(item.rule_conditions)
        )
        cat_conds = [
            c.category
            for c in r_conds
            if isinstance(c, LogsourceCondition) and c.category is not None
        ]
        if isinstance(item.transformation, AddConditionTransformation):
            if any(c in handled_categories for c in cat_conds):
                continue
            if ident.startswith("ocsf_windows_security_"):
                continue
            sanitized_upstream_items.append(item)
        elif isinstance(item.transformation, FieldMappingTransformation):
            if any(c in handled_categories for c in cat_conds):
                continue
            if ident == "ocsf_field_mappings_windows_security":
                continue
            cleaned_map: dict[str | None, str | list[str]] = {
                src: dst
                for src, dst in item.transformation.mapping.items()
                if isinstance(src, str)
                and isinstance(dst, str)
                and src != dst
                and not dst.startswith("unmapped.")
                and dst in KNOWN_OCSF_V14_FIELDS
                and (src, dst) not in invalid_upstream_pairs
            }
            if cleaned_map:
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
        name="ProvLoom OCSF v1.4.0 Pipeline",
        priority=10,
        items=v14_items + sanitized_upstream_items,
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
        "severity_id",
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
