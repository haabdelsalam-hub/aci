#!/usr/bin/env python3
"""Read APIC configuration and export timestamped, re-push-oriented matrices.

This exporter only performs APIC GET requests. It uses the tenant names in the
existing prod_matrix.yml and dmz_matrix.yml as selectors, skips tenants that
are missing or have no EPGs, and discovers every EPG, domain association, and
static path binding in the remaining tenants. Output files use exclusive-create
semantics and are never overwritten.
"""

from __future__ import annotations

import argparse
import getpass
import http.cookiejar
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml


PAGE_SIZE = 500


def object_data(record: dict, class_name: str) -> dict:
    return record.get(class_name, {}) if isinstance(record, dict) else {}


def attrs(record: dict, class_name: str | None = None) -> dict:
    value = object_data(record, class_name) if class_name else record
    return value.get("attributes", {}) if isinstance(value, dict) else {}


def children(record: dict, class_name: str | None = None) -> list[dict]:
    value = object_data(record, class_name) if class_name else record
    return value.get("children", []) if isinstance(value, dict) else []


def class_children(record: dict, class_name: str) -> list[dict]:
    return [row[class_name] for row in children(record) if class_name in row]


def last_dn_part(dn: str) -> str:
    return dn.rsplit("/", 1)[-1] if dn else ""


def named_dn_part(dn: str, prefix: str) -> str:
    part = last_dn_part(dn)
    return part[len(prefix):] if part.startswith(prefix) else part


def parse_vlan(value: str) -> int:
    match = re.fullmatch(r"vlan-(\d+)", str(value))
    if not match:
        raise ValueError(f"Expected a VLAN encapsulation such as vlan-123; got {value!r}")
    return int(match.group(1))


def yaml_int(value: str | int) -> int:
    match = re.search(r"(\d+)$", str(value))
    if not match:
        raise ValueError(f"Could not read a numeric VLAN/port value from {value!r}")
    return int(match.group(1))


def apic_bool(value: object) -> bool:
    return str(value).strip().lower() in {"yes", "true", "1", "enabled"}


class Apic:
    def __init__(self, host: str, username: str, password: str, verify_tls: bool):
        host = host.strip().rstrip("/")
        if not host.startswith(("https://", "http://")):
            host = "https://" + host
        self.base_url = host
        self.username = username
        self.password = password
        self.cookies = http.cookiejar.CookieJar()
        handlers: list[object] = [urllib.request.HTTPCookieProcessor(self.cookies)]
        if self.base_url.startswith("https://"):
            context = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
            handlers.append(urllib.request.HTTPSHandler(context=context))
        self.opener = urllib.request.build_opener(*handlers)

    def request(self, path: str, payload: dict | None = None) -> dict:
        url = self.base_url + path
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST" if payload is not None else "GET",
        )
        try:
            with self.opener.open(request, timeout=45) as response:
                result = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            details = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"APIC returned HTTP {exc.code} for {path}: {details[:800]}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"APIC request failed for {path}: {exc}") from exc
        errors = [row.get("error", {}).get("attributes", {}) for row in result.get("imdata", []) if "error" in row]
        if errors:
            message = "; ".join(f"{e.get('code', '?')}: {e.get('text', 'APIC error')}" for e in errors)
            raise RuntimeError(f"APIC rejected {path}: {message}")
        return result

    def login(self) -> None:
        self.request(
            "/api/aaaLogin.json",
            {"aaaUser": {"attributes": {"name": self.username, "pwd": self.password}}},
        )
        if not any(cookie.name == "APIC-cookie" for cookie in self.cookies):
            raise RuntimeError("APIC login did not return an APIC-cookie; check the host and credentials")

    def query(self, path: str, params: dict[str, str] | None = None) -> list[dict]:
        records: list[dict] = []
        page = 0
        total = None
        while total is None or len(records) < total:
            query = dict(params or {})
            query.update({"page": str(page), "page-size": str(PAGE_SIZE)})
            separator = "&" if "?" in path else "?"
            result = self.request(path + separator + urllib.parse.urlencode(query))
            records.extend(result.get("imdata", []))
            total = int(result.get("totalCount", len(records)))
            if not result.get("imdata") or len(records) >= total:
                break
            page += 1
        return records

    def class_query(self, class_name: str, include_children: bool = True) -> list[dict]:
        params = {"rsp-subtree": "full"} if include_children else None
        records = self.query(f"/api/class/{class_name}.json", params)
        return [record[class_name] for record in records if class_name in record]

    def tenant_query(self, tenant_name: str, class_name: str) -> list[dict]:
        tenant = urllib.parse.quote(tenant_name, safe="-_.")
        return self.query(
            f"/api/node/mo/uni/tn-{tenant}.json",
            {
                "query-target": "subtree",
                "target-subtree-class": class_name,
                "rsp-subtree": "full",
            },
        )


def read_tenant_name(path: Path) -> str:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    tenant = data.get("tenant_name")
    if not tenant:
        raise ValueError(f"{path} has no tenant_name; supply the correct template file")
    return str(tenant)


def get_api_objects(records: list[dict], class_name: str) -> list[dict]:
    return [object_data(record, class_name) for record in records if class_name in record]


def rel_target(child: dict, class_name: str) -> str:
    relation = object_data(child, class_name) if class_name in child else child
    return str(attrs(relation).get("tDn", ""))


def get_policy_group_name(selector: dict) -> str:
    refs = class_children(selector, "infraRsAccBaseGrp")
    return named_dn_part(rel_target(ref, "infraRsAccBaseGrp"), "accbundle-") if refs else ""


def policy_group_aep(group: dict) -> str:
    names = {
        named_dn_part(rel_target(rel, "infraRsAttEntP"), "attentp-")
        for rel in class_children(group, "infraRsAttEntP")
        if rel_target(rel, "infraRsAttEntP")
    }
    if len(names) != 1:
        raise ValueError(
            f"Policy group {attrs(group).get('name', '')!r} resolves to {len(names)} AEPs; "
            f"expected one: {sorted(names)}"
        )
    return next(iter(names))


def vlan_pool_records(domain_names: list[str], domains: list[dict], vlan_pools: list[dict]) -> list[dict]:
    """Return each domain's single VLAN pool, preserving every configured range."""
    domain_by_name = {str(attrs(domain).get("name", "")): domain for domain in domains}
    pool_by_dn = {str(attrs(pool).get("dn", "")): pool for pool in vlan_pools}
    pool_domains: dict[str, set[str]] = {}
    for domain_name in domain_names:
        domain = domain_by_name.get(domain_name)
        if not domain:
            raise ValueError(f"Could not find physical domain {domain_name!r}")
        pool_dns = {
            rel_target(rel, "infraRsVlanNs")
            for rel in class_children(domain, "infraRsVlanNs")
            if rel_target(rel, "infraRsVlanNs")
        }
        if len(pool_dns) != 1:
            raise ValueError(
                f"Physical domain {domain_name!r} references {len(pool_dns)} VLAN pools; "
                f"expected one. APIC pools: {sorted(pool_dns)}"
            )
        pool_dn = next(iter(pool_dns))
        if pool_dn not in pool_by_dn:
            raise ValueError(f"Physical domain {domain_name!r} references VLAN pool {pool_dn!r}, which APIC did not return")
        pool_domains.setdefault(pool_dn, set()).add(domain_name)

    records = []
    for pool_dn, assigned_domains in sorted(pool_domains.items()):
        pool = pool_by_dn[pool_dn]
        p_attrs = attrs(pool)
        blocks = []
        for block in class_children(pool, "fvnsEncapBlk"):
            b_attrs = attrs(block)
            block_start = yaml_int(b_attrs.get("from", ""))
            block_end = yaml_int(b_attrs.get("to", ""))
            allocation_mode = str(b_attrs.get("allocMode", p_attrs.get("allocMode", "static"))).lower()
            block_name = str(b_attrs.get("name", "")).strip()
            if not block_name:
                block_name = f"VLANs_{block_start}_{block_end}_{allocation_mode}"
            blocks.append({
                "block_name": block_name,
                "block_start": block_start,
                "block_end": block_end,
                "allocation_mode": allocation_mode,
            })
        records.append({
            "name": str(p_attrs.get("name", "")),
            "pool_allocation_mode": str(p_attrs.get("allocMode", "static")).lower(),
            "description": str(p_attrs.get("descr", "")),
            "encap_blocks": blocks,
            "domains": sorted(assigned_domains),
        })
    return records


def profile_node_map(node_profiles: list[dict]) -> tuple[dict[int, list[dict]], dict[str, set[int]]]:
    by_node: dict[int, list[dict]] = {}
    profile_nodes: dict[str, set[int]] = {}
    for profile in node_profiles:
        p_attrs = attrs(profile)
        profile_name = str(p_attrs.get("name", ""))
        # APIC creates system profiles for hardware defaults; they are not
        # re-push targets and can overlap user-managed leaf profiles.
        if profile_name.startswith("system-"):
            continue
        interface_profiles = {
            named_dn_part(rel_target(ref, "infraRsAccPortP"), "accportprof-")
            for ref in class_children(profile, "infraRsAccPortP")
            if rel_target(ref, "infraRsAccPortP")
        }
        for selector in class_children(profile, "infraLeafS"):
            s_attrs = attrs(selector)
            blocks = class_children(selector, "infraNodeBlk")
            for block in blocks:
                b_attrs = attrs(block)
                try:
                    first = int(b_attrs.get("from", b_attrs.get("from_")))
                    last = int(b_attrs.get("to", b_attrs.get("to_", first)))
                except (TypeError, ValueError):
                    continue
                for node_id in range(first, last + 1):
                    data = {
                        "node_id": node_id,
                        "switch_profile": profile_name,
                        "leaf_selector": str(s_attrs.get("name", "")),
                        "node_block": str(b_attrs.get("name", "")),
                        "interface_profiles": interface_profiles,
                        "block_from": first,
                        "block_to": last,
                    }
                    if data not in by_node.setdefault(node_id, []):
                        by_node[node_id].append(data)
                    for interface_profile in interface_profiles:
                        profile_nodes.setdefault(interface_profile, set()).add(node_id)
    return by_node, profile_nodes


def port_selector_records(interface_profiles: list[dict]) -> list[dict]:
    result = []
    for profile in interface_profiles:
        profile_attrs = attrs(profile)
        profile_name = str(profile_attrs.get("name", ""))
        profile_dn = str(profile_attrs.get("dn", ""))
        for selector in class_children(profile, "infraHPortS"):
            s_attrs = attrs(selector)
            blocks = class_children(selector, "infraPortBlk")
            if len(blocks) != 1:
                continue
            block_attrs = attrs(blocks[0])
            group_refs = class_children(selector, "infraRsAccBaseGrp")
            if not group_refs:
                continue
            group_dn = rel_target(group_refs[0], "infraRsAccBaseGrp")
            group_part = last_dn_part(group_dn)
            group_name = group_part
            for prefix in ("accbundle-", "accportgrp-"):
                if group_part.startswith(prefix):
                    group_name = group_part[len(prefix):]
                    break
            result.append(
                {
                    "interface_profile": profile_name,
                    "interface_profile_dn": profile_dn,
                    "selector": str(s_attrs.get("name", "")),
                    "port_blk": str(block_attrs.get("name", "")),
                    "from_card": int(block_attrs.get("fromCard", 1)),
                    "from_port": int(block_attrs.get("fromPort", 0)),
                    "to_card": int(block_attrs.get("toCard", 1)),
                    "to_port": int(block_attrs.get("toPort", 0)),
                    "policy_group": group_name,
                    "policy_group_dn": group_dn,
                    "selector_interface_type": "vpc" if "accbundle" in group_dn else "switch_port",
                }
            )
    return result


def parse_static_path(binding: dict) -> dict:
    b_attrs = attrs(binding, "fvRsPathAtt")
    tdn = str(b_attrs.get("tDn", ""))
    match = re.search(
        r"topology/pod-(\d+)/(protpaths|paths)-([\d-]+)(?:/extpaths-(\d+))?/pathep-\[([^\]]+)\]",
        tdn,
    )
    if not match:
        raise ValueError(f"Cannot convert static path DN to this workspace's matrix schema: {tdn!r}")
    pod, path_kind, node_text, extpath, endpoint = match.groups()
    node_ids = [part for part in node_text.split("-") if part]
    if path_kind == "protpaths":
        interface_type = "fex_vpc" if extpath else "vpc"
        interface = endpoint
        leafs: str | list[str] = node_ids
    elif extpath:
        interface_type = "fex"
        interface = endpoint.removeprefix("eth")
        leafs = node_ids[0]
    elif endpoint.startswith("eth"):
        interface_type = "switch_port"
        interface = endpoint.removeprefix("eth")
        leafs = node_ids[0]
    else:
        interface_type = "port_channel"
        interface = endpoint
        leafs = node_ids[0]
    extpaths = [extpath] if extpath else None
    interface_mode = str(b_attrs.get("mode", "regular")).lower()
    interface_mode = {"regular": "trunk", "untagged": "access"}.get(interface_mode, interface_mode)
    return {
        "encap_id": parse_vlan(str(b_attrs.get("encap", ""))),
        "deploy_immediacy": str(b_attrs.get("instrImedcy", "lazy")).lower(),
        "interface_mode": interface_mode,
        "interface_type": interface_type,
        "pod_id": int(pod),
        "leafs": leafs,
        "interface": interface,
        "extpaths": extpaths,
        "description": str(b_attrs.get("descr", "")),
        "state": "present",
        "_path_dn": tdn,
    }


def tenant_matrix(tenant_name: str, epg_records: list[dict], bd_records: list[dict]) -> dict:
    bridge_domains = {
        str(attrs(row, "fvBD").get("dn", "")): row
        for row in bd_records
        if "fvBD" in row
    }
    epgs = []
    bridge_domain_configs: dict[str, dict] = {}
    for record in epg_records:
        epg = object_data(record, "fvAEPg")
        e_attrs = attrs(epg)
        epg_name = str(e_attrs.get("name", ""))
        dn_parts = str(e_attrs.get("dn", "")).split("/")
        if len(dn_parts) < 4 or not dn_parts[2].startswith("ap-"):
            raise ValueError(f"Cannot determine application profile from EPG DN {e_attrs.get('dn')!r}")
        ap_name = dn_parts[2][3:]
        e_children = children(epg)
        bd_relations = class_children(epg, "fvRsBd")
        bd_name = ""
        vrf_name = ""
        if bd_relations:
            relation_attrs = attrs(bd_relations[0])
            bd_dn = str(relation_attrs.get("tDn", ""))
            bd_name = str(relation_attrs.get("tnFvBD", "")) or named_dn_part(bd_dn, "BD-")
            matching_bd = bridge_domains.get(bd_dn)
            if not matching_bd and bd_name:
                matching_bd = next(
                    (row for row in bd_records if attrs(row, "fvBD").get("name") == bd_name),
                    None,
                )
            if matching_bd:
                bd_attrs = attrs(matching_bd, "fvBD")
                for ctx in class_children(object_data(matching_bd, "fvBD"), "fvRsCtx"):
                    ctx_attrs = attrs(ctx)
                    vrf_name = str(ctx_attrs.get("tnFvCtx", ""))
                    if not vrf_name:
                        vrf_name = named_dn_part(str(ctx_attrs.get("tDn", "")), "ctx-")
                    break
                bd_config = {
                    "bd_name": bd_name,
                    "vrf_name": vrf_name,
                    "enable_routing": apic_bool(bd_attrs.get("unicastRoute", "no")),
                    "l2_unknown_unicast": str(bd_attrs.get("unkMacUcastAct", "proxy")).lower(),
                    "arp_flooding": apic_bool(bd_attrs.get("arpFlood", "no")),
                }
                existing_config = bridge_domain_configs.get(bd_name)
                if existing_config and existing_config != bd_config:
                    raise ValueError(
                        f"Bridge domain {bd_name!r} has conflicting APIC definitions: "
                        f"{existing_config} and {bd_config}"
                    )
                bridge_domain_configs[bd_name] = bd_config
        if not bd_name or not vrf_name:
            raise ValueError(f"EPG {epg_name} has no readable bridge domain/VRF relation; cannot make a repush matrix")

        domains = {"vmware": set(), "nutanix": set(), "physical": set()}
        for rel in class_children(epg, "fvRsDomAtt"):
            target = rel_target(rel, "fvRsDomAtt")
            if "/phys-" in target:
                domains["physical"].add(named_dn_part(target, "phys-"))
            elif "/vmmp-VMware/dom-" in target:
                domains["vmware"].add(named_dn_part(target, "dom-"))
            elif "/vmmp-Nutanix/dom-" in target:
                domains["nutanix"].add(named_dn_part(target, "dom-"))

        bindings = []
        for row in class_children(epg, "fvRsPathAtt"):
            parsed = parse_static_path({"fvRsPathAtt": row})
            if parsed.get("extpaths") is None:
                parsed.pop("extpaths")
            parsed.pop("_path_dn")
            bindings.append(parsed)
        bindings.sort(key=lambda b: (b["pod_id"], str(b["leafs"]), str(b["interface"]), b["encap_id"]))
        epgs.append(
            {
                "epg_name": epg_name,
                "bd_name": bd_name,
                "ap_name": ap_name,
                "vrf_name": vrf_name,
                "vmware_domains": sorted(domains["vmware"]),
                "nutanix_domains": sorted(domains["nutanix"]),
                "physical_domains": sorted(domains["physical"]),
                "static_bindings": bindings,
            }
        )
    epgs.sort(key=lambda epg: str(epg["epg_name"]))
    return {
        "tenant_name": tenant_name,
        "bridge_domains": [bridge_domain_configs[name] for name in sorted(bridge_domain_configs)],
        "vlan_migration_list": epgs,
    }


def binding_path_signature(binding: dict) -> tuple:
    leafs = binding.get("leafs", [])
    if isinstance(leafs, (list, tuple)):
        leaf_signature = tuple(str(leaf) for leaf in leafs)
    else:
        leaf_signature = str(leafs)
    extpaths = binding.get("extpaths") or []
    if not isinstance(extpaths, (list, tuple)):
        extpaths = [extpaths]
    return (
        str(binding.get("deploy_immediacy", "lazy")).lower(),
        str(binding.get("interface_mode", "trunk")).lower(),
        str(binding.get("interface_type", "")).lower(),
        int(binding.get("pod_id", 1)),
        leaf_signature,
        str(binding.get("interface", "")),
        tuple(str(path) for path in extpaths),
        str(binding.get("description", "") or ""),
        str(binding.get("state", "present")).lower(),
    )


def compact_static_bindings(matrix: dict, profiles: dict[str, list[dict]]) -> None:
    """Replace exact reusable path sets with profile references in an exported matrix."""
    for epg in matrix.get("vlan_migration_list", []):
        bindings = epg.get("static_bindings", [])
        encaps = {int(binding["encap_id"]) for binding in bindings if "encap_id" in binding}
        if not bindings or len(encaps) != 1:
            continue
        default_encap = next(iter(encaps))
        remaining = list(bindings)
        matched_profiles = []
        for profile_name, profile_bindings in profiles.items():
            if not isinstance(profile_bindings, list) or not profile_bindings:
                continue
            matched_indexes = []
            for profile_binding in profile_bindings:
                if not isinstance(profile_binding, dict):
                    matched_indexes = []
                    break
                profile_encap = int(profile_binding.get("encap_id", default_encap))
                found = next(
                    (
                        index for index, binding in enumerate(remaining)
                        if binding_path_signature(binding) == binding_path_signature(profile_binding)
                        and int(binding["encap_id"]) == profile_encap
                    ),
                    None,
                )
                if found is None or found in matched_indexes:
                    matched_indexes = []
                    break
                matched_indexes.append(found)
            if matched_indexes:
                for index in reversed(matched_indexes):
                    remaining.pop(index)
                matched_profiles.append(profile_name)
        if matched_profiles:
            epg["static_binding_encap_id"] = default_encap
            epg["static_binding_profiles"] = matched_profiles
            if remaining:
                epg["static_bindings"] = remaining
            else:
                epg.pop("static_bindings", None)


def policy_values(group: dict) -> dict[str, str | None]:
    refs = {
        "link_level_policy": "infraRsHIfPol",
        "cdp_policy": "infraRsCdpIfPol",
        "lldp_policy": "infraRsLldpIfPol",
        "port_channel_policy": "infraRsLacpPol",
    }
    values: dict[str, str | None] = {key: None for key in refs}
    for key, class_name in refs.items():
        rels = class_children(group, class_name)
        if rels:
            dn = rel_target(rels[0], class_name)
            values[key] = named_dn_part(dn, "")
            part = last_dn_part(dn)
            if "-" in part:
                values[key] = part.split("-", 1)[1]
    return values


def parse_interface_configs(records: list[dict]) -> list[dict]:
    result = []
    for record in records:
        values = attrs(record)
        assoc_group = str(values.get("assocGrp", ""))
        part = last_dn_part(assoc_group)
        if part.startswith("accbundle-"):
            group_name, interface_type = part[len("accbundle-"):], "pc_or_vpc"
        elif part.startswith("accportgrp-"):
            group_name, interface_type = part[len("accportgrp-"):], "switch_port"
        else:
            continue
        try:
            node, card, port = int(values["node"]), int(values["card"]), int(values["port"])
            sub_port = int(values.get("subPort", 0))
        except (KeyError, TypeError, ValueError):
            continue
        result.append({
            "node": node, "card": card, "port": port, "sub_port": sub_port,
            "interface": f"{card}/{port}/{sub_port}" if sub_port else f"{card}/{port}",
            "interface_type": interface_type, "policy_group": group_name,
            "policy_group_dn": assoc_group, "role": str(values.get("role", "leaf")),
            "description": str(values.get("description", values.get("descr", ""))),
        })
    return result


def static_binding_key(binding: dict) -> tuple:
    leafs = binding["leafs"] if isinstance(binding["leafs"], list) else [binding["leafs"]]
    return (
        binding["encap_id"], binding["interface_type"], binding["pod_id"],
        tuple(str(leaf) for leaf in leafs), binding["interface"],
    )


def per_port_static_access(
    all_bindings: list[dict], interface_configs: list[dict], bundle_groups: list[dict],
    access_groups: list[dict], aeps: list[dict], physical_domains: list[dict], vlan_pools: list[dict],
) -> dict | None:
    if not interface_configs:
        return None
    bundle_by_name = {str(attrs(row).get("name", "")): row for row in bundle_groups}
    access_by_name = {str(attrs(row).get("name", "")): row for row in access_groups}
    aep_by_name = {str(attrs(row).get("name", "")): row for row in aeps}
    matched_configs = {}
    covered_bindings = set()
    for binding in all_bindings:
        if binding["interface_type"] == "vpc":
            nodes = {int(node) for node in binding["leafs"]}
            matches = [c for c in interface_configs if c["policy_group"] == binding["interface"] and c["node"] in nodes]
            if {c["node"] for c in matches} != nodes:
                continue
        elif binding["interface_type"] == "switch_port":
            card, port = (int(value) for value in str(binding["interface"]).split("/", 1))
            node = int(binding["leafs"])
            matches = [c for c in interface_configs if (c["node"], c["card"], c["port"]) == (node, card, port)]
            if not matches:
                continue
        else:
            continue
        covered_bindings.add(static_binding_key(binding))
        for config in matches:
            key = (config["node"], config["card"], config["port"], config["sub_port"])
            matched_configs[key] = config

    if not matched_configs:
        return None

    group_names = {c["policy_group"] for c in matched_configs.values()}
    groups, group_modes = [], {}
    for name in sorted(group_names):
        if name in bundle_by_name:
            group, mode = bundle_by_name[name], str(attrs(bundle_by_name[name]).get("lagT", "node")).lower()
        elif name in access_by_name:
            group, mode = access_by_name[name], "leaf"
        else:
            raise ValueError(f"Per-port interface config refers to missing policy group {name!r}")
        groups.append((name, group))
        group_modes[name] = mode

    group_aep_names = {name: policy_group_aep(group) for name, group in groups}
    aep_names = set(group_aep_names.values())
    aep_name = sorted(aep_names)[0]
    missing_aeps = sorted(aep_names - set(aep_by_name))
    if missing_aeps:
        raise ValueError(f"Could not find APIC attachable entity profiles {missing_aeps}")

    policy_groups = []
    for name, group in groups:
        values = policy_values(group)
        policy_groups.append({
            "policy_group": name, "lag_type": group_modes[name], "aep": group_aep_names[name],
            "link_level_policy": values.get("link_level_policy"),
            "cdp_policy": values.get("cdp_policy"), "lldp_policy": values.get("lldp_policy"),
            "port_channel_policy": values.get("port_channel_policy"),
            "description": str(attrs(group).get("descr", "")), "state": "present",
        })

    aep_domains = {
        name: sorted({
            named_dn_part(rel_target(rel, "infraRsDomP"), "phys-")
            for rel in class_children(aep_by_name[name], "infraRsDomP")
            if "/phys-" in rel_target(rel, "infraRsDomP")
        })
        for name in sorted(aep_names)
    }
    physical_domain_names = sorted({domain for domains in aep_domains.values() for domain in domains})
    if not physical_domain_names:
        return None
    pool_records = vlan_pool_records(physical_domain_names, physical_domains, vlan_pools)
    if not pool_records:
        raise ValueError("Per-port AEP domains do not reference any VLAN pools")
    required = {int(binding["encap_id"]) for binding in all_bindings}
    available = {
        vlan
        for pool_record in pool_records
        for block in pool_record["encap_blocks"]
        for vlan in range(block["block_start"], block["block_end"] + 1)
    }
    missing = sorted(required - available)
    if missing:
        print(
            f"Warning: static EPG VLANs {missing} are outside all VLAN pools associated with the selected domains; "
            "the export will preserve the live values, but repush behavior may depend on APIC accepting "
            "static encapsulations outside those pools.",
            file=sys.stderr,
        )

    port_configs = [
        {
            "node": c["node"], "interface": c["interface"], "interface_type": c["interface_type"],
            "policy_group": c["policy_group"], "role": c["role"],
            "description": c["description"], "state": "present",
        }
        for c in sorted(matched_configs.values(), key=lambda row: (row["node"], row["card"], row["port"], row["sub_port"]))
    ]
    return {
        "static_aep": aep_name,
        "static_aep_domains": [{"aep": name, "domains": domains} for name, domains in aep_domains.items()],
        "static_physical_domains": physical_domain_names,
        "static_vlan_pools": pool_records,
        "static_vlan_pool": {
            "name": pool_records[0]["name"],
            "pool_allocation_mode": pool_records[0]["pool_allocation_mode"],
            "description": pool_records[0]["description"],
            "encap_blocks": pool_records[0]["encap_blocks"],
        },
        "static_interface_policy_defaults": {
            "link_level_policy": None, "cdp_policy": None, "lldp_policy": None, "port_channel_policy": None,
        },
        "static_leaf_profiles": [], "static_switch_selectors": [], "static_vpc_selector_bindings": [],
        "static_vpc_trunks": [], "static_vpc_access_ports": [],
        "static_single_access_policy_group": "", "static_single_access_ports": [],
        "static_interface_policy_groups": policy_groups, "static_interface_configs": port_configs,
        "_covered_binding_keys": covered_bindings,
    }


def parse_static_access(
    tenant_matrices: list[dict],
    node_profiles: list[dict],
    interface_profiles: list[dict],
    bundle_groups: list[dict],
    access_groups: list[dict],
    aeps: list[dict],
    physical_domains: list[dict],
    vlan_pools: list[dict],
    interface_config_records: list[dict],
) -> dict:
    by_node, profile_nodes = profile_node_map(node_profiles)
    selectors = port_selector_records(interface_profiles)
    bundle_by_name = {str(attrs(row).get("name", "")): row for row in bundle_groups}
    access_by_name = {str(attrs(row).get("name", "")): row for row in access_groups}
    aep_by_name = {str(attrs(row).get("name", "")): row for row in aeps}

    all_bindings = [binding for matrix in tenant_matrices for epg in matrix["vlan_migration_list"] for binding in epg["static_bindings"]]
    parsed_interface_configs = parse_interface_configs(interface_config_records)
    per_port_config = per_port_static_access(
        all_bindings,
        parsed_interface_configs,
        bundle_groups,
        access_groups,
        aeps,
        physical_domains,
        vlan_pools,
    )
    if per_port_config is not None:
        covered = per_port_config.pop("_covered_binding_keys")
        legacy_bindings = [binding for binding in all_bindings if static_binding_key(binding) not in covered]
        if not legacy_bindings:
            return per_port_config
    else:
        covered = set()
        legacy_bindings = all_bindings
    unsupported_types = sorted({binding["interface_type"] for binding in legacy_bindings} - {"vpc", "switch_port"})
    if unsupported_types:
        raise ValueError(
            f"Static paths use interface types {unsupported_types} that task_configure_static_access_ports.yml cannot rebuild"
        )
    vpc_names = {str(binding["interface"]) for binding in legacy_bindings if binding["interface_type"] == "vpc"}
    vpc_modes: dict[str, list[str]] = {}
    for binding in legacy_bindings:
        if binding["interface"] in vpc_names:
            vpc_modes.setdefault(str(binding["interface"]), []).append(str(binding["interface_mode"]))

    selected_vpc = [selector for selector in selectors if selector["policy_group"] in vpc_names]
    single_bindings = [binding for binding in legacy_bindings if binding["interface_type"] == "switch_port"]
    selected_single = []
    for binding in single_bindings:
        leaf_ids = [int(binding["leafs"])] if isinstance(binding["leafs"], str) else [int(node) for node in binding["leafs"]]
        port_match = re.fullmatch(r"(\d+)/(\d+)", str(binding["interface"]))
        if not port_match:
            raise ValueError(f"Cannot map direct static path {binding['interface']!r} to an access selector")
        card, port = map(int, port_match.groups())
        for leaf_id in leaf_ids:
            leaves = by_node.get(leaf_id, [])
            if not leaves:
                raise ValueError(f"Static path uses leaf {leaf_id}, but no switch policy profile selects it")
            profiles = {name for leaf in leaves for name in leaf["interface_profiles"]}
            candidates = [
                selector for selector in selectors
                if selector["interface_profile"] in profiles
                and selector["from_card"] <= card <= selector["to_card"]
                and selector["from_port"] <= port <= selector["to_port"]
            ]
            if len(candidates) != 1:
                known = [
                    f"{selector['interface_profile']}:{selector['selector']} "
                    f"{selector['from_card']}/{selector['from_port']}-{selector['to_card']}/{selector['to_port']} "
                    f"-> {selector['policy_group']}"
                    for selector in selectors
                ]
                raise ValueError(
                    f"Static path to leaf {leaf_id} port {card}/{port} maps to {len(candidates)} access selectors; "
                    f"expected exactly one. APIC selectors: {known[:20]}"
                )
            selected_single.append((leaf_id, candidates[0]))

    # Interface defaults remain common, while each policy group keeps its own AEP.
    relevant_group_names = vpc_names | {selector["policy_group"] for _, selector in selected_single}
    relevant_groups = [bundle_by_name[name] for name in sorted(vpc_names) if name in bundle_by_name]
    relevant_groups += [access_by_name[name] for name in sorted(relevant_group_names - vpc_names) if name in access_by_name]
    if vpc_names - set(bundle_by_name):
        raise ValueError(f"No APIC vPC policy group found for {sorted(vpc_names - set(bundle_by_name))}")
    if relevant_group_names - set(bundle_by_name) - set(access_by_name):
        raise ValueError(f"No APIC access policy group found for {sorted(relevant_group_names - set(bundle_by_name) - set(access_by_name))}")

    group_aep_names = {
        str(attrs(group).get("name", "")): policy_group_aep(group)
        for group in relevant_groups
    }
    aep_names = set(group_aep_names.values())
    if per_port_config:
        aep_names.update(row["aep"] for row in per_port_config["static_aep_domains"])
    if not aep_names:
        raise ValueError("Static access policy groups do not reference an AEP")
    aep_name = sorted(aep_names)[0]
    missing_aeps = sorted(aep_names - set(aep_by_name))
    if missing_aeps:
        raise ValueError(f"Could not find APIC attachable entity profiles {missing_aeps}")
    defaults = {
        "link_level_policy": set(),
        "cdp_policy": set(),
        "lldp_policy": set(),
        "port_channel_policy": set(),
    }
    for group in relevant_groups:
        for key, value in policy_values(group).items():
            if value:
                defaults[key].add(value)
    interface_defaults = {
        key: next(iter(values)) if len(values) == 1 else None
        for key, values in defaults.items()
    }

    aep_domains = {
        name: {
            named_dn_part(rel_target(rel, "infraRsDomP"), "phys-")
            for rel in class_children(aep_by_name[name], "infraRsDomP")
            if "/phys-" in rel_target(rel, "infraRsDomP")
        }
        for name in aep_names
    }
    if per_port_config:
        for row in per_port_config["static_aep_domains"]:
            aep_domains[row["aep"]].update(row["domains"])
    physical_domain_names = sorted(
        {domain for domains in aep_domains.values() for domain in domains}
        | (set(per_port_config["static_physical_domains"]) if per_port_config else set())
    )
    if not physical_domain_names:
        physical_domain_names = sorted(
            {
                domain
                for matrix in tenant_matrices
                for epg in matrix["vlan_migration_list"]
                for domain in epg["physical_domains"]
            }
        )

    pool_records = vlan_pool_records(physical_domain_names, physical_domains, vlan_pools)
    if not pool_records:
        raise ValueError("The selected physical domains do not reference any VLAN pools")
    primary_pool = pool_records[0]
    pool_name = primary_pool["name"]
    pool_blocks = primary_pool["encap_blocks"]
    required_encaps = {int(binding["encap_id"]) for binding in all_bindings}
    available_encaps = {
        vlan
        for pool_record in pool_records
        for block in pool_record["encap_blocks"]
        for vlan in range(block["block_start"], block["block_end"] + 1)
    }
    missing_encaps = sorted(required_encaps - available_encaps)
    if missing_encaps:
        print(
            f"Warning: static EPG VLANs {missing_encaps} are outside all VLAN pools associated with the selected domains; "
            "the export will preserve the live values, but repush behavior may depend on APIC accepting "
            "static encapsulations outside those pools.",
            file=sys.stderr,
        )

    # Create one leaf-profile record for each leaf used by a captured path.
    used_leafs: set[int] = set()
    for binding in legacy_bindings:
        values = binding["leafs"] if isinstance(binding["leafs"], list) else [binding["leafs"]]
        used_leafs.update(int(value) for value in values)
    static_leaf_profiles = []
    for node_id in sorted(used_leafs):
        leaves = by_node.get(node_id, [])
        if not leaves:
            raise ValueError(f"No switch policy profile selects leaf {node_id}")
        node_vpc_groups = {
            str(binding["interface"])
            for binding in legacy_bindings
            if binding["interface_type"] == "vpc"
            and node_id in {
                int(leaf)
                for leaf in (binding["leafs"] if isinstance(binding["leafs"], list) else [binding["leafs"]])
            }
        }
        used_profiles = sorted({
            selector["interface_profile"]
            for selector in selected_vpc
            if selector["policy_group"] in node_vpc_groups
            and any(selector["interface_profile"] in leaf["interface_profiles"] for leaf in leaves)
        } | {
            selector["interface_profile"]
            for leaf_id, selector in selected_single
            if leaf_id == node_id
        })
        if not used_profiles:
            raise ValueError(
                f"Leaf {node_id} has no relevant interface profile for its captured static paths. "
                f"Candidates: {[(leaf['switch_profile'], leaf['leaf_selector'], sorted(leaf['interface_profiles'])) for leaf in leaves]}"
            )
        for interface_profile in used_profiles:
            matching_leaves = [leaf for leaf in leaves if interface_profile in leaf["interface_profiles"]]
            identities = {
                (leaf["switch_profile"], leaf["leaf_selector"], leaf["node_block"], leaf["block_from"], leaf["block_to"])
                for leaf in matching_leaves
            }
            if len(identities) != 1:
                raise ValueError(
                    f"Leaf {node_id} has {len(identities)} switch selectors for relevant interface profile "
                    f"{interface_profile!r}: {sorted(identities)}"
                )
            leaf = matching_leaves[0]
            static_leaf_profiles.append(
                {
                    "node_id": node_id,
                    "switch_profile": leaf["switch_profile"],
                    "leaf_selector": leaf["leaf_selector"],
                    "node_block": leaf["node_block"],
                    "block_from": leaf["block_from"],
                    "block_to": leaf["block_to"],
                    "interface_profile": interface_profile,
                }
            )

    switch_selector_map = {}
    for leaf in static_leaf_profiles:
        key = (
            leaf["switch_profile"], leaf["leaf_selector"], leaf["node_block"],
            leaf["block_from"], leaf["block_to"],
        )
        switch_selector_map[key] = {
            "switch_profile": leaf["switch_profile"],
            "leaf_selector": leaf["leaf_selector"],
            "node_block": leaf["node_block"],
            "block_from": leaf["block_from"],
            "block_to": leaf["block_to"],
        }
    static_switch_selectors = [switch_selector_map[key] for key in sorted(switch_selector_map)]

    vpc_trunks = []
    vpc_access = []
    grouped_vpc: dict[tuple[str, str], list[dict]] = {}
    for selector in selected_vpc:
        grouped_vpc.setdefault((selector["selector"], selector["policy_group"]), []).append(selector)
    represented_vpc_groups = {group_name for _, group_name in grouped_vpc}
    missing_vpc_groups = sorted(vpc_names - represented_vpc_groups)
    if missing_vpc_groups:
        raise ValueError(f"APIC has no access-port selector for vPC EPG paths {missing_vpc_groups}")
    for (selector_name, group_name), records in sorted(grouped_vpc.items()):
        matching_bindings = [binding for binding in legacy_bindings if binding["interface"] == group_name and binding["interface_type"] in {"vpc", "fex_vpc"}]
        expected_leafs = sorted({int(leaf) for binding in matching_bindings for leaf in binding["leafs"]})
        if not expected_leafs:
            continue
        by_profile = {row["interface_profile"]: row for row in records}
        chosen = []
        for leaf_id in expected_leafs:
            candidates = {
                profile
                for leaf in by_node.get(leaf_id, [])
                for profile in leaf["interface_profiles"]
                if profile in by_profile
            }
            if len(candidates) != 1:
                raise ValueError(
                    f"vPC selector {selector_name} / {group_name} maps to {len(candidates)} interface profiles "
                    f"on leaf {leaf_id}: {sorted(candidates)}"
                )
            profile_name = next(iter(candidates))
            chosen.append(by_profile[profile_name])
        port_ids = {(row["from_port"], row["to_port"], row["from_card"], row["to_card"]) for row in chosen}
        block_names = {row["port_blk"] for row in chosen}
        if len(port_ids) != 1 or len(block_names) != 1:
            raise ValueError(f"vPC selector {selector_name} differs between leaves and cannot be represented by the current task")
        from_port, to_port, from_card, to_card = next(iter(port_ids))
        if from_port != to_port or from_card != 1 or to_card != 1:
            raise ValueError(f"vPC selector {selector_name} is not a single card-1 port; current task assumes that layout")
        member_ports = [f"leaf{leaf_id}:{from_card}/{from_port}" for leaf_id in expected_leafs]
        modes = vpc_modes.get(group_name, [])
        mode = modes[0] if modes else "regular"
        item = {
            "interface": group_name,
            "aep": group_aep_names[group_name],
            **policy_values(bundle_by_name[group_name]),
            "interface_profiles": sorted({row["interface_profile"] for row in chosen}),
            "access_port_selector": selector_name,
            "port_blk": next(iter(block_names)),
            "port_id": from_port,
            "member_ports": member_ports,
            "pod_id": min(binding["pod_id"] for binding in matching_bindings),
            "leafs": [str(value) for value in expected_leafs],
            "interface_type": "vpc",
            "interface_mode": mode,
            "deploy_immediacy": matching_bindings[0]["deploy_immediacy"],
            "description": attrs(bundle_by_name[group_name]).get("descr", ""),
            "state": "present",
        }
        if any(mode in {"regular", "tagged", "trunk"} for mode in modes):
            vpc_trunks.append(item)
        else:
            vpc_access.append(item)

    single_access_ports = []
    seen_single = set()
    single_policy_names = set()
    for leaf_id, selector in selected_single:
        key = (leaf_id, selector["interface_profile"], selector["selector"], selector["policy_group"])
        if key in seen_single:
            continue
        seen_single.add(key)
        single_policy_names.add(selector["policy_group"])
        single_access_ports.append(
            {
                "interface_profile": selector["interface_profile"],
                "access_port_selector": selector["selector"],
                "port_blk": selector["port_blk"],
                "from_card": selector["from_card"],
                "from_port": selector["from_port"],
                "to_card": selector["to_card"],
                "to_port": selector["to_port"],
                "leaf": str(leaf_id),
                "policy_group": selector["policy_group"],
                "interface_type": "switch_port",
                "state": "present",
            }
        )
    single_group = next(iter(single_policy_names), "")

    single_policy_groups = [
        {
            "policy_group": name,
            "aep": policy_group_aep(access_by_name[name]),
            **policy_values(access_by_name[name]),
        }
        for name in sorted(single_policy_names)
    ]

    # Preserve each live AEP's domain associations. Several AEPs may share
    # domains, while each AEP can also have its own domain set.
    aep_domain_map = {name: set(domains) for name, domains in aep_domains.items()}
    if not any(aep_domain_map.values()):
        fallback_domains = set(physical_domain_names)
        if not fallback_domains:
            fallback_domains = {
                domain
                for matrix in tenant_matrices
                for epg in matrix["vlan_migration_list"]
                for domain in epg["physical_domains"]
            }
        aep_domain_map[aep_name].update(fallback_domains)
    static_aep_domains = [
        {"aep": name, "domains": sorted(domains)}
        for name, domains in sorted(aep_domain_map.items())
    ]

    vpc_selector_bindings = [
        {"binding": binding, "interface_profile": interface_profile}
        for binding in vpc_trunks + vpc_access
        for interface_profile in binding["interface_profiles"]
    ]

    return {
        "static_aep": aep_name,
        "static_aep_domains": static_aep_domains,
        "static_physical_domains": physical_domain_names,
        "static_vlan_pools": pool_records,
        "static_vlan_pool": {
            "name": pool_name,
            "pool_allocation_mode": primary_pool["pool_allocation_mode"],
            "description": primary_pool["description"],
            "encap_blocks": pool_blocks,
        },
        "static_interface_policy_defaults": interface_defaults,
        "static_leaf_profiles": static_leaf_profiles,
        "static_switch_selectors": static_switch_selectors,
        "static_vpc_selector_bindings": vpc_selector_bindings,
        "static_vpc_trunks": vpc_trunks,
        "static_vpc_access_ports": vpc_access,
        "static_single_access_policy_group": single_group,
        "static_single_access_policy_groups": single_policy_groups,
        "static_single_access_ports": single_access_ports,
        "static_interface_policy_groups": (per_port_config or {}).get("static_interface_policy_groups", []),
        "static_interface_configs": (per_port_config or {}).get("static_interface_configs", []),
    }


def reserve_output_paths(directory: Path, tenant_roles: list[str]) -> tuple[str, dict[str, Path]]:
    stamp = time.strftime("%Y%m%d_%H%M%S")
    counter = 1
    while True:
        suffix = f"{stamp}_{counter:02d}"
        paths = {"static": directory / f"static_access_matrix_generated_{suffix}.yml"}
        paths.update({
            role: directory / f"{role}_matrix_generated_{suffix}.yml"
            for role in tenant_roles
        })
        if not any(path.exists() for path in paths.values()):
            return suffix, paths
        counter += 1


def write_new_files(paths: dict[str, Path], content: dict[str, dict]) -> None:
    created: list[Path] = []
    try:
        for key, path in paths.items():
            with path.open("x", encoding="utf-8") as stream:
                created.append(path)
                yaml.safe_dump(content[key], stream, sort_keys=False, allow_unicode=True, default_flow_style=False)
    except Exception:
        for path in created:
            path.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read APIC and create new, timestamped static/prod/DMZ matrix YAML files. No APIC objects are modified."
    )
    parser.add_argument("--apic", help="APIC hostname or URL; defaults to inventory.yml's apic1.ansible_host")
    parser.add_argument("--username", default="admin", help="APIC username (default: admin)")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS certificate verification for self-signed APIC certificates")
    parser.add_argument("--output-dir", type=Path, default=Path("."), help="Directory for generated YAML files")
    parser.add_argument("--prod-template", type=Path, default=Path("prod_matrix.yml"), help="File supplying the production tenant name")
    parser.add_argument("--dmz-template", type=Path, default=Path("dmz_matrix.yml"), help="File supplying the DMZ tenant name")
    parser.add_argument(
        "--binding-profiles", type=Path, default=Path("static_binding_profiles.yml"),
        help="File containing reusable static binding profiles",
    )
    args = parser.parse_args()

    try:
        output_dir = args.output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        inventory = yaml.safe_load(Path("inventory.yml").read_text(encoding="utf-8")) or {}
        inventory_host = inventory.get("all", {}).get("hosts", {}).get("apic1", {}).get("ansible_host", "")
        host = args.apic or input(f"APIC host/URL [{inventory_host}]: ").strip() or str(inventory_host)
        if not host:
            raise ValueError("No APIC hostname provided; use --apic or configure inventory.yml")
        password = getpass.getpass(f"APIC password for {args.username}: ")
        template_tenants = {
            "prod": read_tenant_name(args.prod_template),
            "dmz": read_tenant_name(args.dmz_template),
        }
        if template_tenants["prod"] == template_tenants["dmz"]:
            raise ValueError("Production and DMZ templates resolve to the same tenant; refusing ambiguous output")
        binding_profiles: dict[str, list[dict]] = {}
        if args.binding_profiles.exists():
            profile_data = yaml.safe_load(args.binding_profiles.read_text(encoding="utf-8")) or {}
            binding_profiles = profile_data.get("static_binding_profiles", {})
            if not isinstance(binding_profiles, dict):
                raise ValueError(f"{args.binding_profiles} must define static_binding_profiles as a mapping")
        else:
            print(
                f"Binding profile file {args.binding_profiles} not found; exported bindings will remain inline.",
                file=sys.stderr,
            )

        apic = Apic(host, args.username, password, verify_tls=not args.insecure)
        print(f"Logging in to {host} and reading APIC configuration (read-only)...", file=sys.stderr)
        apic.login()
        live_tenants = {
            str(attrs(tenant).get("name", ""))
            for tenant in apic.class_query("fvTenant", include_children=False)
            if attrs(tenant).get("name")
        }
        print(f"APIC tenants found: {', '.join(sorted(live_tenants)) or '(none)'}")

        tenant_matrices: dict[str, dict] = {}
        ignored_tenants: list[tuple[str, str, str]] = []
        for role, tenant_name in template_tenants.items():
            if tenant_name not in live_tenants:
                ignored_tenants.append((role, tenant_name, "not present on APIC"))
                continue
            epg_records = apic.tenant_query(tenant_name, "fvAEPg")
            if not epg_records:
                ignored_tenants.append((role, tenant_name, "no EPGs found"))
                continue
            bd_records = apic.tenant_query(tenant_name, "fvBD")
            matrix_data = tenant_matrix(tenant_name, epg_records, bd_records)
            tenant_matrices[role] = matrix_data

        for role, tenant_name, reason in ignored_tenants:
            print(f"Ignored {role} tenant {tenant_name!r}: {reason}.")
        if not tenant_matrices:
            print("No configured tenants were exportable; no matrix files were created.")
            return 0

        static = parse_static_access(
            list(tenant_matrices.values()),
            apic.class_query("infraNodeP"),
            apic.class_query("infraAccPortP"),
            apic.class_query("infraAccBndlGrp"),
            apic.class_query("infraAccPortGrp"),
            apic.class_query("infraAttEntityP"),
            apic.class_query("physDomP"),
            apic.class_query("fvnsVlanInstP"),
            apic.class_query("infraPortConfig", include_children=False),
        )
        # Catch incomplete or malformed output before creating any files.
        for tenant_matrix_data in tenant_matrices.values():
            for epg in tenant_matrix_data["vlan_migration_list"]:
                if not epg["ap_name"] or not epg["vrf_name"]:
                    raise ValueError(f"EPG {epg['epg_name']!r} is missing an application profile or VRF")
                for binding in epg["static_bindings"]:
                    required = ("encap_id", "deploy_immediacy", "interface_mode", "interface_type", "pod_id", "leafs", "interface")
                    missing = [field for field in required if field not in binding or binding[field] in (None, "", [])]
                    if missing:
                        raise ValueError(f"EPG {epg['epg_name']!r} has a static path missing {missing}")
        for tenant_matrix_data in tenant_matrices.values():
            compact_static_bindings(tenant_matrix_data, binding_profiles)
        content = {"static": static, **tenant_matrices}
        _, paths = reserve_output_paths(output_dir, list(tenant_matrices))
        write_new_files(paths, content)
        for role, matrix_data in tenant_matrices.items():
            print(f"Exported {role} tenant {matrix_data['tenant_name']!r}.")
        print("Created:")
        for path in paths.values():
            print(f"  {path}")
        print("Review the generated YAML before running any configure/bind playbook.")
        return 0
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, IndexError, yaml.YAMLError) as exc:
        print(f"Export failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
