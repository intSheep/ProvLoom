from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from typing import Any

from provloom.domain.entity_models import CandidateKey, EntityObservation
from provloom.domain.enums import EntityType, OcsfClassUid
from provloom.domain.ocsf_models import NormalizedEvent
from provloom.entity.interfaces import EntityExtractor
from provloom.parsing.time_utils import parse_utc_timestamp


def _norm_path(path: str) -> str:
    if "\\" in path or (len(path) >= 2 and path[1] == ":"):
        return path.replace("/", "\\").lower()
    return path


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class OcsfEntityExtractor(EntityExtractor):
    def supports_class(self, class_uid: int) -> bool:
        return class_uid != int(OcsfClassUid.BASE_EVENT)

    def extract(self, event: NormalizedEvent) -> Sequence[EntityObservation]:
        p = event.ocsf_payload
        ts = event.event_time
        obs: list[EntityObservation] = []

        # 1. Host (must resolve first so host-scoped entities can reference its entity_id)
        host_obs = self._extract_host(p, event)
        if host_obs is not None:
            obs.append(host_obs)

        # 2. Container
        cont = p.get("container")
        if isinstance(cont, dict) and cont.get("uid"):
            cid = str(cont["uid"]).strip().lower()
            keys = (
                (CandidateKey("container_id", cid, is_authoritative=True),)
                if len(cid) >= 32
                else (
                    CandidateKey(
                        "short_container_id", cid, is_authoritative=True, scope_role="host"
                    ),
                )
            )
            obs.append(
                EntityObservation(
                    role="container",
                    entity_type=EntityType.CONTAINER,
                    display_label=f"container:{cid[:12]}",
                    observed_at=ts,
                    candidate_keys=keys,
                    attributes={k: v for k, v in cont.items() if v is not None},
                )
            )

        # 3. User
        actor_raw = p.get("actor")
        actor: dict[str, Any] = actor_raw if isinstance(actor_raw, dict) else {}
        user_cand = p.get("user") if isinstance(p.get("user"), dict) else actor.get("user")
        if isinstance(user_cand, dict):
            u_obs = self._extract_user(user_cand, event)
            if u_obs is not None:
                obs.append(u_obs)

        # 4. Parent & Actor Process
        proc_obj = p.get("process") if isinstance(p.get("process"), dict) else actor.get("process")
        if isinstance(proc_obj, dict):
            parent_obj = proc_obj.get("parent_process")
            if isinstance(parent_obj, dict):
                p_obs = self._extract_process(
                    parent_obj, "parent_process", event, is_launch=False, is_terminate=False
                )
                if p_obs is not None:
                    obs.append(p_obs)

            is_launch = (
                event.class_uid == int(OcsfClassUid.PROCESS_ACTIVITY) and event.activity_id == 1
            )
            is_term = (
                event.class_uid == int(OcsfClassUid.PROCESS_ACTIVITY) and event.activity_id == 2
            )
            a_obs = self._extract_process(
                proc_obj, "actor_process", event, is_launch=is_launch, is_terminate=is_term
            )
            if a_obs is not None:
                obs.append(a_obs)

        # 5. File
        file_obj = p.get("file")
        if isinstance(file_obj, dict) and file_obj.get("path"):
            raw_path = str(file_obj["path"])
            fkeys: list[CandidateKey] = [
                CandidateKey(
                    "host_file_path", _norm_path(raw_path), is_authoritative=True, scope_role="host"
                )
            ]
            hashes_raw = file_obj.get("hashes")
            hashes: dict[str, Any] = hashes_raw if isinstance(hashes_raw, dict) else {}
            if hashes.get("sha256"):
                fkeys.append(
                    CandidateKey("sha256", str(hashes["sha256"]).lower(), is_authoritative=False)
                )
            obs.append(
                EntityObservation(
                    role="target_file",
                    entity_type=EntityType.FILE,
                    display_label=raw_path,
                    observed_at=ts,
                    candidate_keys=tuple(fkeys),
                    attributes={"path": raw_path, **hashes},
                )
            )

        # 6. Service
        svc_obj = p.get("service")
        if isinstance(svc_obj, dict) and svc_obj.get("name"):
            sname = str(svc_obj["name"])
            sport = svc_obj.get("port")
            skey = f"{sname.lower()}:{sport if sport is not None else '*'}"
            obs.append(
                EntityObservation(
                    role="service",
                    entity_type=EntityType.SERVICE,
                    display_label=f"{sname}:{sport}" if sport else sname,
                    observed_at=ts,
                    candidate_keys=(
                        CandidateKey(
                            "host_service", skey, is_authoritative=True, scope_role="host"
                        ),
                    ),
                    attributes={k: v for k, v in svc_obj.items() if v is not None},
                )
            )

        # 7. Network Endpoints & DNS Answers
        proto_raw = (
            p.get("connection_info", {}).get("protocol_name")
            if isinstance(p.get("connection_info"), dict)
            else None
        )
        proto = str(proto_raw or "ip").lower()

        src_ep = p.get("src_endpoint")
        if isinstance(src_ep, dict) and src_ep.get("ip"):
            sip = str(src_ep["ip"])
            obs.append(
                EntityObservation(
                    role="src_endpoint",
                    entity_type=EntityType.NETWORK_ENDPOINT,
                    display_label=sip,
                    observed_at=ts,
                    candidate_keys=(
                        CandidateKey("endpoint", f"{sip}/*", is_authoritative=True),
                        CandidateKey("ip", sip, is_authoritative=False),
                    ),
                    attributes={"ip": sip, "port": src_ep.get("port"), "protocol": proto},
                )
            )

        dst_ep = p.get("dst_endpoint")
        if isinstance(dst_ep, dict) and dst_ep.get("ip"):
            dip = str(dst_ep["ip"])
            dport = dst_ep.get("port")
            ep_key = f"{dip}:{dport}/{proto}" if dport is not None else f"{dip}/*"
            label = f"{dip}:{dport}/{proto}" if dport is not None else dip
            obs.append(
                EntityObservation(
                    role="dst_endpoint",
                    entity_type=EntityType.NETWORK_ENDPOINT,
                    display_label=label,
                    observed_at=ts,
                    candidate_keys=(
                        CandidateKey("endpoint", ep_key, is_authoritative=True),
                        CandidateKey("ip", dip, is_authoritative=False),
                    ),
                    attributes={"ip": dip, "port": dport, "protocol": proto},
                )
            )

        if event.class_uid == int(OcsfClassUid.DNS_ACTIVITY):
            raw_answers = p.get("answers")
            ans_list: list[str] = []
            if isinstance(raw_answers, list):
                ans_list = [str(x).strip() for x in raw_answers]
            elif isinstance(raw_answers, str):
                ans_list = [s.strip() for s in raw_answers.replace(",", ";").split(";")]
            idx = 0
            for ans in ans_list:
                if ans and _is_ip(ans):
                    obs.append(
                        EntityObservation(
                            role=f"dns_answer_{idx}",
                            entity_type=EntityType.NETWORK_ENDPOINT,
                            display_label=ans,
                            observed_at=ts,
                            candidate_keys=(
                                CandidateKey("endpoint", f"{ans}/*", is_authoritative=True),
                                CandidateKey("ip", ans, is_authoritative=False),
                            ),
                            attributes={"ip": ans},
                        )
                    )
                    idx += 1

        return obs

    def _extract_host(
        self, payload: dict[str, Any], event: NormalizedEvent
    ) -> EntityObservation | None:
        dev = payload.get("device") if isinstance(payload.get("device"), dict) else None
        dst_ep = (
            payload.get("dst_endpoint") if isinstance(payload.get("dst_endpoint"), dict) else None
        )

        hostname: str | None = None
        asset_id: str | None = None
        ip: str | None = None
        is_nat = False
        vf = None
        vt = None
        attrs: dict[str, Any] = {}

        if dev:
            asset_id = str(dev["uid"]) if dev.get("uid") else None
            hostname = str(dev["hostname"]) if dev.get("hostname") else None
            ip = str(dev["ip"]) if dev.get("ip") else None
            is_nat = bool(dev.get("is_nat_shared", False))
            if dev.get("valid_from"):
                vf = parse_utc_timestamp(dev["valid_from"])
            if dev.get("valid_to"):
                vt = parse_utc_timestamp(dev["valid_to"])
            attrs.update({k: v for k, v in dev.items() if v is not None})
        elif (
            event.class_uid == int(OcsfClassUid.AUTHENTICATION)
            and dst_ep
            and dst_ep.get("hostname")
        ):
            hostname = str(dst_ep["hostname"])
            attrs["hostname"] = hostname

        if not any((asset_id, hostname, ip)):
            return None

        keys: list[CandidateKey] = []
        if asset_id:
            keys.append(CandidateKey("asset_id", asset_id, is_authoritative=True))
        if hostname:
            h_clean = hostname.strip().lower()
            # Only FQDN or asset-backed hostname is authoritative; short names stay provisional.
            if "." in h_clean or asset_id:
                keys.append(CandidateKey("fqdn", h_clean, is_authoritative=True))
            else:
                keys.append(CandidateKey("short_hostname", h_clean, is_authoritative=False))
        if ip:
            if not is_nat and (asset_id or (hostname and "." in hostname)):
                keys.append(CandidateKey("host_ip_lease", ip, is_authoritative=True))
            else:
                keys.append(CandidateKey("observed_ip", ip, is_authoritative=False))

        label = hostname or asset_id or str(ip)
        return EntityObservation(
            role="host",
            entity_type=EntityType.HOST,
            display_label=label,
            observed_at=event.event_time,
            candidate_keys=tuple(keys),
            attributes=attrs,
            lifecycle_start=vf,
            lifecycle_end=vt,
        )

    def _extract_user(
        self, user_obj: dict[str, Any], event: NormalizedEvent
    ) -> EntityObservation | None:
        raw_name = str(user_obj["name"]).strip() if user_obj.get("name") else ""
        domain = str(user_obj["domain"]).strip() if user_obj.get("domain") else ""
        sid = str(user_obj["uid"]).strip() if user_obj.get("uid") else ""

        if "\\" in raw_name and not domain:
            domain, raw_name = raw_name.split("\\", 1)

        if not raw_name and not sid:
            return None

        keys: list[CandidateKey] = []
        if sid and (sid.upper().startswith("S-1-5-21-") or ":" in sid):
            keys.append(CandidateKey("user_sid", sid, is_authoritative=True))
        if (
            domain
            and domain.lower() not in {".", "local", "workgroup", "nt authority"}
            and raw_name
        ):
            keys.append(
                CandidateKey(
                    "domain_user", f"{domain.lower()}\\{raw_name.lower()}", is_authoritative=True
                )
            )
        elif raw_name:
            keys.append(
                CandidateKey(
                    "local_user", raw_name.lower(), is_authoritative=True, scope_role="host"
                )
            )

        label = f"{domain}\\{raw_name}" if domain and raw_name else (raw_name or sid)
        return EntityObservation(
            role="user",
            entity_type=EntityType.USER,
            display_label=label,
            observed_at=event.event_time,
            candidate_keys=tuple(keys),
            attributes={"name": raw_name, "domain": domain or None, "uid": sid or None},
        )

    def _extract_process(
        self,
        proc_obj: dict[str, Any],
        role: str,
        event: NormalizedEvent,
        is_launch: bool,
        is_terminate: bool,
    ) -> EntityObservation | None:
        guid_raw = str(proc_obj["uid"]).strip() if proc_obj.get("uid") else ""
        pid_val = proc_obj.get("pid")
        file_raw = proc_obj.get("file")
        file_obj: dict[str, Any] = file_raw if isinstance(file_raw, dict) else {}
        image = str(file_obj.get("path") or proc_obj.get("name") or "").strip()
        cmd = str(proc_obj["cmd_line"]).strip() if proc_obj.get("cmd_line") else None

        if not any((guid_raw, pid_val is not None, image)):
            return None

        keys: list[CandidateKey] = []
        if guid_raw:
            norm_guid = guid_raw.strip("{}").lower()
            keys.append(
                CandidateKey("process_guid", norm_guid, is_authoritative=True, scope_role="host")
            )
        if pid_val is not None:
            keys.append(
                CandidateKey("host_pid", str(pid_val), is_authoritative=True, scope_role="host")
            )
        if image:
            exe_name = image.replace("/", "\\").rsplit("\\", 1)[-1]
            keys.append(CandidateKey("process_name", exe_name.lower(), is_authoritative=False))
        else:
            exe_name = f"pid:{pid_val}"

        label = f"{exe_name} (PID {pid_val})" if pid_val is not None else exe_name
        return EntityObservation(
            role=role,
            entity_type=EntityType.PROCESS,
            display_label=label,
            observed_at=event.event_time,
            candidate_keys=tuple(keys),
            attributes={
                "pid": pid_val,
                "process_guid": guid_raw or None,
                "image": image or None,
                "cmd_line": cmd,
                "is_launch": is_launch,
                "is_terminate": is_terminate,
            },
            lifecycle_start=event.event_time if is_launch else None,
            lifecycle_end=event.event_time if is_terminate else None,
        )
