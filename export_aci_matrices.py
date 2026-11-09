#!/usr/bin/env python3
"""Read APIC configuration and export timestamped, re-push-oriented matrices.

This exporter only performs APIC GET requests. It uses the tenant names in the
existing prod_matrix.yml and dmz_matrix.yml as selectors, then discovers every
EPG, domain association, and static path binding currently present in those
tenants. Output files are created with exclusive-create semantics and are never
overwritten.
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


def tenant_from_dn(dn: str) -> str:
    parts = dn.split("/")
    return parts[1][3:] if len(parts) > 1 and parts[1].startswith("tn-") else ""


def choose_live_tenant(expected: str, role: str, epg_tenants: set[str], excluded: set[str]) -> str:
    if expected in epg_tenants:
        return expected
    system_tenants = {"infra", "common", "mgmt"}
    candidates = {
        tenant for tenant in epg_tenants
        if tenant not in system_tenants and tenant not in excluded
    }
    keyword_matches = {
        tenant for tenant in candidates
        if ("dmz" in tenant.lower() if role == "dmz" else any(token in tenant.lower() for token in ("prod", "production")))
    }
    if len(keyword_matches) == 1:
        selected = next(iter(keyword_matches))
    elif not keyword_matches and len(candidates) == 1:
        selected = next(iter(candidates))
    else:
        raise ValueError(
            f"Template tenant {expected!r} has no EPGs, and APIC does not have one unambiguous {role} tenant. "
            f"Candidates with EPGs: {sorted(candidates)}"
        )
    print(
        f"Using APIC tenant {selected!r} for {role}; template tenant {expected!r} has no EPGs.",
        file=sys.stderr,
    )
    return selected


def get_api_objects(records: list[dict], class_name: str) -> list[dict]:
    return [object_data(record, class_name) for record in records if class_name in record]


def rel_target(child: dict, class_name: str) -> str:
    relation = object_data(child, class_name) if class_name in child else child
    return str(attrs(relation).get("tDn", ""))


def get_policy_group_name(selector: dict) -> str:
    refs = class_children(selector, "infraRsAccBaseGrp")
    return named_dn_part(rel_target(ref, "infraRsAccBaseGrp"), "accbundle-") if refs else ""


def profile_node_map(node_profiles: list[dict]) -> tuple[dict[int, dict], dict[str, set[int]]]:
    by_node: dict[int, dict] = {}
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
                    if node_id in by_node and by_node[node_id] != data:
                        previous = by_node[node_id]
                        raise ValueError(
                            f"Leaf {node_id} is selected more than once: "
                            f"{previous['switch_profile']}/{previous['leaf_selector']} "
                            f"(block {previous['node_block']}, interface profiles {sorted(previous['interface_profiles'])}) and "
                            f"{data['switch_profile']}/{data['leaf_selector']} "
                            f"(block {data['node_block']}, interface profiles {sorted(data['interface_profiles'])})"
                        )
                    by_node[node_id] = data
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
    return {
        "encap_id": parse_vlan(str(b_attrs.get("encap", ""))),
        "deploy_immediacy": str(b_attrs.get("instrImedcy", "lazy")).lower(),
        "interface_mode": str(b_attrs.get("mode", "regular")).lower(),
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
    for record in epg_records:
        epg = object_data(record, "fvAEPg")
        e_attrs = attrs(epg)
        epg_name = str(e_attrs.get("name", ""))
        epg_id_text = epg_name[4:] if epg_name.startswith("EPG-") else epg_name
        epg_id: str | int = int(epg_id_text) if epg_id_text.isdigit() else epg_id_text
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
                for ctx in class_children(object_data(matching_bd, "fvBD"), "fvRsCtx"):
                    ctx_attrs = attrs(ctx)
                    vrf_name = str(ctx_attrs.get("tnFvCtx", ""))
                    if not vrf_name:
                        vrf_name = named_dn_part(str(ctx_attrs.get("tDn", "")), "ctx-")
                    break
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
            parsed.update({"enabled": True})
            bindings.append(parsed)
        bindings.sort(key=lambda b: (b["pod_id"], str(b["leafs"]), str(b["interface"]), b["encap_id"]))
        encap_ids = sorted({binding["encap_id"] for binding in bindings})
        epgs.append(
            {
                "epg_name": epg_id,
                "epg_object_name": epg_name,
                "bd_name": bd_name,
                "encap_id": encap_ids[0] if encap_ids else None,
                "name": epg_name,
                "ap_name": ap_name,
                "vrf_name": vrf_name,
                "vmware_domains": sorted(domains["vmware"]),
                "nutanix_domains": sorted(domains["nutanix"]),
                "physical_domains": sorted(domains["physical"]),
                "static_bindings": bindings,
            }
        )
    epgs.sort(key=lambda epg: str(epg["epg_name"]))
    return {"tenant_name": tenant_name, "vlan_migration_list": epgs}


def policy_values(group: dict) -> dict[str, str]:
    refs = {
        "link_level_policy": "infraRsHIfPol",
        "cdp_policy": "infraRsCdpIfPol",
        "lldp_policy": "infraRsLldpIfPol",
        "port_channel_policy": "infraRsLacpPol",
    }
    values = {}
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

    aep_names = {
        named_dn_part(rel_target(rel, "infraRsAttEntP"), "attentp-")
        for _, group in groups for rel in class_children(group, "infraRsAttEntP")
        if rel_target(rel, "infraRsAttEntP")
    }
    if len(aep_names) != 1:
        raise ValueError(f"Per-port policy groups resolve to {len(aep_names)} AEPs: {sorted(aep_names)}")
    aep_name = next(iter(aep_names))
    if aep_name not in aep_by_name:
        raise ValueError(f"Could not find APIC attachable entity profile {aep_name!r}")

    policy_groups = []
    for name, group in groups:
        values = policy_values(group)
        policy_groups.append({
            "policy_group": name, "lag_type": group_modes[name], "aep": aep_name,
            "link_level_policy": values.get("link_level_policy"),
            "cdp_policy": values.get("cdp_policy"), "lldp_policy": values.get("lldp_policy"),
            "port_channel_policy": values.get("port_channel_policy"),
            "description": str(attrs(group).get("descr", "")), "state": "present",
        })

    physical_domain_names = sorted({
        named_dn_part(rel_target(rel, "infraRsDomP"), "phys-")
        for rel in class_children(aep_by_name[aep_name], "infraRsDomP")
        if "/phys-" in rel_target(rel, "infraRsDomP")
    })
    if not physical_domain_names:
        return None
    pool_dns = {
        rel_target(rel, "infraRsVlanNs")
        for domain in physical_domains if attrs(domain).get("name") in physical_domain_names
        for rel in class_children(domain, "infraRsVlanNs") if rel_target(rel, "infraRsVlanNs")
    }
    pool_by_dn = {str(attrs(pool).get("dn", "")): pool for pool in vlan_pools}
    pools = [pool_by_dn[dn] for dn in sorted(pool_dns) if dn in pool_by_dn]
    if len(pools) != 1:
        raise ValueError(f"Per-port AEP domains reference {len(pools)} VLAN pools; one is required by this task")
    pool, p_attrs = pools[0], attrs(pools[0])
    blocks = []
    for block in class_children(pool, "fvnsEncapBlk"):
        b_attrs = attrs(block)
        blocks.append({
            "block_name": str(b_attrs.get("name", "")),
            "block_start": yaml_int(b_attrs.get("from", "")),
            "block_end": yaml_int(b_attrs.get("to", "")),
            "allocation_mode": str(b_attrs.get("allocMode", p_attrs.get("allocMode", "static"))).lower(),
        })
    required = {int(binding["encap_id"]) for binding in all_bindings}
    available = {vlan for block in blocks for vlan in range(block["block_start"], block["block_end"] + 1)}
    missing = sorted(required - available)
    if missing:
        print(
            f"Warning: static EPG VLANs {missing} are outside APIC VLAN pool {p_attrs.get('name')!r}; "
            "the export will preserve both live values, but repush behavior may depend on APIC accepting "
            "static encapsulations outside the pool.",
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
        "static_physical_domains": physical_domain_names,
        "static_vlan_pool": {
            "name": str(p_attrs.get("name", "")),
            "pool_allocation_mode": str(p_attrs.get("allocMode", "static")).lower(),
            "description": str(p_attrs.get("descr", "")), "encap_blocks": blocks,
        },
        "static_interface_policy_defaults": {
            "link_level_policy": None, "cdp_policy": None, "lldp_policy": None, "port_channel_policy": None,
        },
        "static_leaf_profiles": [], "static_vpc_trunks": [], "static_vpc_access_ports": [],
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
            leaf = by_node.get(leaf_id)
            if not leaf:
                raise ValueError(f"Static path uses leaf {leaf_id}, but no switch policy profile selects it")
            candidates = [
                selector for selector in selectors
                if selector["interface_profile"] in leaf["interface_profiles"]
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

    # The task schema has one common AEP and one common set of interface defaults.
    relevant_group_names = vpc_names | {selector["policy_group"] for _, selector in selected_single}
    relevant_groups = [bundle_by_name[name] for name in sorted(vpc_names) if name in bundle_by_name]
    relevant_groups += [access_by_name[name] for name in sorted(relevant_group_names - vpc_names) if name in access_by_name]
    if vpc_names - set(bundle_by_name):
        raise ValueError(f"No APIC vPC policy group found for {sorted(vpc_names - set(bundle_by_name))}")
    if relevant_group_names - set(bundle_by_name) - set(access_by_name):
        raise ValueError(f"No APIC access policy group found for {sorted(relevant_group_names - set(bundle_by_name) - set(access_by_name))}")

    aep_names = {per_port_config["static_aep"]} if per_port_config else set()
    for group in relevant_groups:
        for rel in class_children(group, "infraRsAttEntP"):
            target = rel_target(rel, "infraRsAttEntP")
            if target:
                aep_names.add(named_dn_part(target, "attentp-"))
    if len(aep_names) != 1:
        raise ValueError(f"Static access policy groups resolve to {len(aep_names)} AEPs; this task schema supports one: {sorted(aep_names)}")
    aep_name = next(iter(aep_names))
    aep = aep_by_name.get(aep_name)
    if not aep:
        raise ValueError(f"Could not find APIC attachable entity profile {aep_name!r}")

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
    for key, values in defaults.items():
        if len(values) > 1:
            raise ValueError(f"Static access policy groups use multiple {key} values; the current matrix supports one: {sorted(values)}")
    interface_defaults = {key: next(iter(values)) if values else None for key, values in defaults.items()}

    physical_domain_names = sorted(
        {
            named_dn_part(rel_target(rel, "infraRsDomP"), "phys-")
            for rel in class_children(aep, "infraRsDomP")
            if "/phys-" in rel_target(rel, "infraRsDomP")
        }
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

    pool_dns = set()
    for domain in physical_domains:
        if attrs(domain).get("name") in physical_domain_names:
            for rel in class_children(domain, "infraRsVlanNs"):
                target = rel_target(rel, "infraRsVlanNs")
                if target:
                    pool_dns.add(target)
    pool_by_dn = {str(attrs(pool).get("dn", "")): pool for pool in vlan_pools}
    matching_pools = [pool_by_dn[dn] for dn in sorted(pool_dns) if dn in pool_by_dn]
    if len(matching_pools) != 1:
        raise ValueError(
            f"The selected physical domains reference {len(matching_pools)} VLAN pools; this matrix schema supports one. "
            "Review the pool associations before re-pushing."
        )
    pool = matching_pools[0]
    p_attrs = attrs(pool)
    pool_blocks = []
    for block in class_children(pool, "fvnsEncapBlk"):
        b_attrs = attrs(block)
        pool_blocks.append(
            {
                "block_name": str(b_attrs.get("name", "")),
                "block_start": yaml_int(b_attrs.get("from", "")),
                "block_end": yaml_int(b_attrs.get("to", "")),
                "allocation_mode": str(b_attrs.get("allocMode", p_attrs.get("allocMode", "static"))).lower(),
            }
        )
    pool_name = str(p_attrs.get("name", ""))
    required_encaps = {int(binding["encap_id"]) for binding in all_bindings}
    available_encaps = {
        vlan
        for block in pool_blocks
        for vlan in range(block["block_start"], block["block_end"] + 1)
    }
    missing_encaps = sorted(required_encaps - available_encaps)
    if missing_encaps:
        print(
            f"Warning: static EPG VLANs {missing_encaps} are outside APIC VLAN pool {pool_name!r}; "
            "the export will preserve both live values, but repush behavior may depend on APIC accepting "
            "static encapsulations outside the pool.",
            file=sys.stderr,
        )

    # Create one leaf-profile record for each leaf used by a captured path.
    used_leafs: set[int] = set()
    for binding in legacy_bindings:
        values = binding["leafs"] if isinstance(binding["leafs"], list) else [binding["leafs"]]
        used_leafs.update(int(value) for value in values)
    static_leaf_profiles = []
    for node_id in sorted(used_leafs):
        leaf = by_node.get(node_id)
        if not leaf:
            raise ValueError(f"No switch policy profile selects leaf {node_id}")
        if leaf["block_from"] != leaf["block_to"]:
            raise ValueError(
                f"Leaf {node_id} belongs to selector range {leaf['block_from']}-{leaf['block_to']}; "
                "task_configure_static_access_ports.yml only supports one node per selector"
            )
        interface_names = sorted(leaf["interface_profiles"])
        used_profiles = sorted(
            name for name in interface_names
            if any(s["interface_profile"] == name for s in selected_vpc)
            or any(s["interface_profile"] == name for _, s in selected_single)
        )
        if len(used_profiles) != 1:
            raise ValueError(f"Leaf {node_id} maps to {len(used_profiles)} relevant interface profiles; expected one")
        static_leaf_profiles.append(
            {
                "node_id": node_id,
                "switch_profile": leaf["switch_profile"],
                "leaf_selector": leaf["leaf_selector"],
                "node_block": leaf["node_block"],
                "interface_profile": used_profiles[0],
            }
        )

    leaf_profile_by_node = {row["node_id"]: row for row in static_leaf_profiles}
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
        if expected_leafs != sorted(used_leafs):
            raise ValueError(
                f"The current vPC selector task applies every vPC to every static leaf; {group_name} uses {expected_leafs}, "
                f"while the tenant matrices use {sorted(used_leafs)}. The task schema cannot safely represent these paths."
            )
        by_profile = {row["interface_profile"]: row for row in records}
        chosen = []
        for leaf_id in expected_leafs:
            profile_name = leaf_profile_by_node[leaf_id]["interface_profile"]
            if profile_name not in by_profile:
                raise ValueError(f"vPC selector {selector_name} / {group_name} is missing from interface profile {profile_name}")
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
    if len(single_policy_names) > 1:
        raise ValueError(
            f"Direct static ports use multiple leaf policy groups {sorted(single_policy_names)}; "
            "task_configure_static_access_ports.yml currently accepts one static_single_access_policy_group"
        )
    single_group = next(iter(single_policy_names), "")

    return {
        "static_aep": aep_name,
        "static_physical_domains": physical_domain_names,
        "static_vlan_pool": {
            "name": pool_name,
            "pool_allocation_mode": str(p_attrs.get("allocMode", "static")).lower(),
            "description": str(p_attrs.get("descr", "")),
            "encap_blocks": pool_blocks,
        },
        "static_interface_policy_defaults": interface_defaults,
        "static_leaf_profiles": static_leaf_profiles,
        "static_vpc_trunks": vpc_trunks,
        "static_vpc_access_ports": vpc_access,
        "static_single_access_policy_group": single_group,
        "static_single_access_ports": single_access_ports,
        "static_interface_policy_groups": (per_port_config or {}).get("static_interface_policy_groups", []),
        "static_interface_configs": (per_port_config or {}).get("static_interface_configs", []),
    }


def reserve_output_paths(directory: Path) -> tuple[str, dict[str, Path]]:
    stamp = time.strftime("%Y%m%d_%H%M%S")
    counter = 1
    while True:
        suffix = f"{stamp}_{counter:02d}"
        paths = {
            "static": directory / f"static_access_matrix_generated_{suffix}.yml",
            "prod": directory / f"prod_matrix_generated_{suffix}.yml",
            "dmz": directory / f"dmz_matrix_generated_{suffix}.yml",
        }
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
        prod_tenant = read_tenant_name(args.prod_template)
        dmz_tenant = read_tenant_name(args.dmz_template)
        if prod_tenant == dmz_tenant:
            raise ValueError("Production and DMZ templates resolve to the same tenant; refusing ambiguous output")

        apic = Apic(host, args.username, password, verify_tls=not args.insecure)
        print(f"Logging in to {host} and reading APIC configuration (read-only)...", file=sys.stderr)
        apic.login()
        live_tenants = {
            str(attrs(tenant).get("name", ""))
            for tenant in apic.class_query("fvTenant", include_children=False)
            if attrs(tenant).get("name")
        }
        epg_index = apic.class_query("fvAEPg", include_children=False)
        epg_tenants = {
            tenant_from_dn(str(attrs(epg).get("dn", "")))
            for epg in epg_index
            if tenant_from_dn(str(attrs(epg).get("dn", "")))
        }
        prod_tenant = choose_live_tenant(prod_tenant, "production", epg_tenants, {dmz_tenant})
        dmz_tenant = choose_live_tenant(dmz_tenant, "DMZ", epg_tenants, {prod_tenant})
        prod_epg_records = apic.tenant_query(prod_tenant, "fvAEPg")
        prod_bd_records = apic.tenant_query(prod_tenant, "fvBD")
        dmz_epg_records = apic.tenant_query(dmz_tenant, "fvAEPg")
        dmz_bd_records = apic.tenant_query(dmz_tenant, "fvBD")
        if not prod_epg_records:
            raise ValueError(
                f"APIC indexed EPGs under {prod_tenant!r} but the tenant-scoped EPG query returned none"
            )
        if not dmz_epg_records:
            raise ValueError(f"APIC returned no EPGs for DMZ tenant {dmz_tenant!r}")
        prod = tenant_matrix(
            prod_tenant,
            prod_epg_records,
            prod_bd_records,
        )
        dmz = tenant_matrix(
            dmz_tenant,
            dmz_epg_records,
            dmz_bd_records,
        )
        static = parse_static_access(
            [prod, dmz],
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
        for tenant_matrix_data in (prod, dmz):
            for epg in tenant_matrix_data["vlan_migration_list"]:
                if not epg["ap_name"] or not epg["vrf_name"]:
                    raise ValueError(f"EPG {epg['name']!r} is missing an application profile or VRF")
                for binding in epg["static_bindings"]:
                    required = ("encap_id", "deploy_immediacy", "interface_mode", "interface_type", "pod_id", "leafs", "interface")
                    missing = [field for field in required if field not in binding or binding[field] in (None, "", [])]
                    if missing:
                        raise ValueError(f"EPG {epg['name']!r} has a static path missing {missing}")
        _, paths = reserve_output_paths(output_dir)
        write_new_files(paths, {"static": static, "prod": prod, "dmz": dmz})
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
