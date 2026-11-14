#!/usr/bin/env python3
"""Convert tenant or static-access matrices between CSV and YAML."""

import argparse
import csv
import json
from pathlib import Path

import yaml

REQUIRED_COLUMNS = {
    "tenant_name", "epg_name", "ap_name", "vrf_name",
    "vmware_domains", "nutanix_domains", "physical_domains",
}
LIST_COLUMNS = ("vmware_domains", "nutanix_domains", "physical_domains")
TENANT_CSV_COLUMNS = (
    "tenant_name", "epg_name", "ap_name", "vrf_name", "bd_name",
    "bd_enable_routing", "bd_l2_unknown_unicast", "bd_arp_flooding",
    "static_binding_encap_id", "static_binding_profiles", "static_bindings",
    "vmware_domains", "nutanix_domains", "physical_domains",
)
REQUIRED_BINDING_FIELDS = {
    "encap_id", "deploy_immediacy", "interface_mode", "interface_type",
    "pod_id", "leafs", "interface", "state",
}


class MatrixDumper(yaml.SafeDumper):
    """Keep repeated path data readable instead of emitting YAML aliases."""

    def ignore_aliases(self, data):
        return True


def parse_json_cell(value, column, line_number):
    value = (value or "").strip()
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError(f"line {line_number}: {column} must be valid JSON: {exc}") from exc
    if not isinstance(parsed, list):
        raise ValueError(f"line {line_number}: {column} must be a JSON array")
    return parsed


def json_cell(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def parse_bool_cell(value, column, line_number, default):
    value = (value or "").strip().lower()
    if not value:
        return default
    if value in {"true", "yes", "1", "enabled"}:
        return True
    if value in {"false", "no", "0", "disabled"}:
        return False
    raise ValueError(f"line {line_number}: {column} must be true or false")


def convert(csv_path, yaml_path):
    with csv_path.open(newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        missing = REQUIRED_COLUMNS - set(reader.fieldnames or [])
        if missing:
            raise ValueError("CSV is missing required columns: " + ", ".join(sorted(missing)))

        rows = []
        tenants = set()
        bridge_domains = {}
        for line_number, raw in enumerate(reader, start=2):
            if not any((value or "").strip() for value in raw.values()):
                continue
            tenant = (raw["tenant_name"] or "").strip()
            if not tenant:
                raise ValueError(f"line {line_number}: tenant_name is required")
            tenants.add(tenant)
            row = {
                "epg_name": (raw["epg_name"] or "").strip(),
                "ap_name": (raw["ap_name"] or "").strip(),
                "vrf_name": (raw["vrf_name"] or "").strip(),
                "bd_name": (raw.get("bd_name") or "").strip() or (raw["epg_name"] or "").strip(),
            }
            bd_config = {
                "bd_name": row["bd_name"],
                "vrf_name": row["vrf_name"],
                "enable_routing": parse_bool_cell(raw.get("bd_enable_routing"), "bd_enable_routing", line_number, False),
                "l2_unknown_unicast": (raw.get("bd_l2_unknown_unicast") or "flood").strip().lower(),
                "arp_flooding": parse_bool_cell(raw.get("bd_arp_flooding"), "bd_arp_flooding", line_number, True),
            }
            if bd_config["l2_unknown_unicast"] not in {"flood", "proxy"}:
                raise ValueError(f"line {line_number}: bd_l2_unknown_unicast must be flood or proxy")
            existing_bd = bridge_domains.get(row["bd_name"])
            if existing_bd and existing_bd != bd_config:
                raise ValueError(
                    f"line {line_number}: EPGs sharing bridge domain {row['bd_name']!r} must use the same VRF and BD settings; "
                    f"existing: {existing_bd}, current: {bd_config}"
                )
            bridge_domains[row["bd_name"]] = bd_config
            for column in LIST_COLUMNS:
                row[column] = parse_json_cell(raw[column], column, line_number)
            bindings = parse_json_cell(raw.get("static_bindings"), "static_bindings", line_number)
            profile_names = parse_json_cell(
                raw.get("static_binding_profiles"), "static_binding_profiles", line_number
            )

            if not all(row[key] for key in ("epg_name", "ap_name", "vrf_name")):
                raise ValueError(f"line {line_number}: epg_name, ap_name, and vrf_name are required")
            if not bindings and not profile_names:
                raise ValueError(f"line {line_number}: EPG needs static_bindings or static_binding_profiles")
            for binding in bindings:
                if not isinstance(binding, dict):
                    raise ValueError(f"line {line_number}: each static binding must be a JSON object")
                binding.pop("enabled", None)
                if not REQUIRED_BINDING_FIELDS.issubset(binding):
                    missing_fields = REQUIRED_BINDING_FIELDS - set(binding)
                    raise ValueError(f"line {line_number}: static binding is missing: {', '.join(sorted(missing_fields))}")
            if any(not isinstance(name, str) or not name.strip() for name in profile_names):
                raise ValueError(f"line {line_number}: static_binding_profiles must contain profile names")
            if bindings:
                row["static_bindings"] = bindings
            if profile_names:
                encap_value = (raw.get("static_binding_encap_id") or "").strip()
                if not encap_value:
                    raise ValueError(f"line {line_number}: profile references require static_binding_encap_id")
                try:
                    row["static_binding_encap_id"] = int(encap_value)
                except ValueError as exc:
                    raise ValueError(f"line {line_number}: static_binding_encap_id must be an integer") from exc
                row["static_binding_profiles"] = profile_names
            rows.append(row)

    if not rows:
        raise ValueError("CSV contains no EPG rows")
    if len(tenants) != 1:
        raise ValueError("CSV must contain rows for exactly one tenant")

    matrix = {
        "tenant_name": tenants.pop(),
        "bridge_domains": list(bridge_domains.values()),
        "vlan_migration_list": rows,
    }
    with yaml_path.open("w", encoding="utf-8") as destination:
        yaml.dump(matrix, destination, Dumper=MatrixDumper, sort_keys=False, allow_unicode=True)


STATIC_COLUMNS = (
    "static_aep", "static_physical_domains", "static_vlan_pool",
    "static_aep_domains",
    "static_vlan_pools",
    "static_interface_policy_defaults", "static_leaf_profiles", "static_vpc_trunks",
    "static_switch_selectors",
    "static_vpc_selector_bindings",
    "static_vpc_access_ports", "static_single_access_policy_group",
    "static_single_access_policy_groups",
    "static_single_access_ports", "static_interface_policy_groups", "static_interface_configs",
)
STATIC_OPTIONAL_COLUMNS = {
    "static_aep_domains", "static_vlan_pools", "static_switch_selectors", "static_vpc_selector_bindings", "static_single_access_policy_groups",
    "static_interface_policy_groups", "static_interface_configs",
}


def convert_static_access(csv_path, yaml_path):
    """Convert one-row CSV whose nested matrix fields are JSON values."""
    with csv_path.open(newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        missing = set(STATIC_COLUMNS) - STATIC_OPTIONAL_COLUMNS - set(reader.fieldnames or [])
        if missing:
            raise ValueError("Static-access CSV is missing columns: " + ", ".join(sorted(missing)))
        rows = [row for row in reader if any((value or "").strip() for value in row.values())]
    if len(rows) != 1:
        raise ValueError("Static-access CSV must contain exactly one non-empty row")
    raw = rows[0]
    matrix = {}
    for key in STATIC_COLUMNS:
        value = (raw.get(key) or "").strip()
        if key in {"static_aep", "static_single_access_policy_group"}:
            matrix[key] = value
            continue
        if not value and key in STATIC_OPTIONAL_COLUMNS:
            matrix[key] = []
            continue
        if not value:
            raise ValueError(f"Static-access field {key} cannot be empty; use [] or {{}} for empty collections")
        try:
            matrix[key] = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Static-access field {key} must contain valid JSON: {exc}") from exc
    if not matrix["static_aep"] or not isinstance(matrix["static_vlan_pool"], dict):
        raise ValueError("static_aep must be non-empty and static_vlan_pool must be a JSON object")
    for key in ("static_physical_domains", "static_aep_domains", "static_vlan_pools", "static_leaf_profiles", "static_switch_selectors", "static_vpc_selector_bindings", "static_vpc_trunks", "static_vpc_access_ports", "static_single_access_policy_groups", "static_single_access_ports", "static_interface_policy_groups", "static_interface_configs"):
        if not isinstance(matrix[key], list):
            raise ValueError(f"{key} must be a JSON array")
    with yaml_path.open("w", encoding="utf-8") as destination:
        yaml.dump(matrix, destination, Dumper=MatrixDumper, sort_keys=False, allow_unicode=True)


def write_csv(csv_path, fieldnames, rows):
    with csv_path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def convert_tenant_yaml_to_csv(yaml_path, csv_path):
    """Convert a tenant YAML matrix to one CSV row per EPG."""
    matrix = yaml.safe_load(yaml_path.read_text(encoding="utf-8-sig")) or {}
    tenant_name = matrix.get("tenant_name")
    epgs = matrix.get("vlan_migration_list")
    if not tenant_name or not isinstance(epgs, list) or not epgs:
        raise ValueError(f"{yaml_path} must contain tenant_name and a non-empty vlan_migration_list")

    bridge_domains = {
        bd.get("bd_name"): bd
        for bd in (matrix.get("bridge_domains") or [])
        if isinstance(bd, dict) and bd.get("bd_name")
    }
    rows = []
    for index, epg in enumerate(epgs, start=1):
        if not isinstance(epg, dict):
            raise ValueError(f"EPG entry {index} must be a mapping")
        bd_name = epg.get("bd_name", epg.get("epg_name", ""))
        bd = bridge_domains.get(bd_name, {})
        bindings = epg.get("static_bindings", [])
        profiles = epg.get("static_binding_profiles", [])
        if not isinstance(bindings, list) or not isinstance(profiles, list):
            raise ValueError(f"EPG {epg.get('epg_name', index)!r} static bindings and profile references must be lists")
        if not bindings and not profiles:
            raise ValueError(f"EPG {epg.get('epg_name', index)!r} has no static bindings or profile references")
        row = {
            "tenant_name": tenant_name,
            "epg_name": epg.get("epg_name", ""),
            "ap_name": epg.get("ap_name", ""),
            "vrf_name": epg.get("vrf_name", ""),
            "bd_name": bd_name,
            "bd_enable_routing": str(bd["enable_routing"]).lower() if "enable_routing" in bd else "",
            "bd_l2_unknown_unicast": bd.get("l2_unknown_unicast", ""),
            "bd_arp_flooding": str(bd["arp_flooding"]).lower() if "arp_flooding" in bd else "",
            "static_binding_encap_id": epg.get("static_binding_encap_id", ""),
            "static_binding_profiles": json_cell(profiles),
            "static_bindings": json_cell(bindings),
        }
        for key in ("vmware_domains", "nutanix_domains", "physical_domains"):
            row[key] = json_cell(epg.get(key, []))
        rows.append(row)
    write_csv(csv_path, TENANT_CSV_COLUMNS, rows)


def convert_static_access_yaml_to_csv(yaml_path, csv_path):
    """Convert one static-access YAML matrix into its one-row CSV form."""
    matrix = yaml.safe_load(yaml_path.read_text(encoding="utf-8-sig")) or {}
    if not isinstance(matrix, dict):
        raise ValueError(f"{yaml_path} must contain a YAML mapping")
    row = {}
    for key in STATIC_COLUMNS:
        if key not in matrix and key not in STATIC_OPTIONAL_COLUMNS:
            raise ValueError(f"{yaml_path} is missing required static-access field {key}")
        value = matrix.get(key, [] if key in STATIC_OPTIONAL_COLUMNS else "")
        if key in {"static_aep", "static_single_access_policy_group"}:
            row[key] = "" if value is None else str(value)
        elif isinstance(value, (dict, list)):
            row[key] = json_cell(value)
        elif value is None:
            row[key] = ""
        else:
            raise ValueError(f"{yaml_path} field {key} must be a mapping or list")
    write_csv(csv_path, STATIC_COLUMNS, [row])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    default_dir = Path(__file__).resolve().parent
    parser.add_argument("--type", choices=("tenant", "static_access"), default="tenant", help="Matrix schema")
    parser.add_argument("--reverse", action="store_true", help="Convert YAML to CSV instead of CSV to YAML")
    parser.add_argument("input", nargs="?", type=Path)
    parser.add_argument("output", nargs="?", type=Path)
    args = parser.parse_args()
    input_path = args.input or default_dir / ("input.yaml" if args.reverse else "input.csv")
    output_path = args.output or default_dir / ("output.csv" if args.reverse else "output.yaml")
    try:
        if args.reverse:
            converter = convert_static_access_yaml_to_csv if args.type == "static_access" else convert_tenant_yaml_to_csv
        else:
            converter = convert_static_access if args.type == "static_access" else convert
        converter(input_path, output_path)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        parser.error(str(exc))
    print(f"Wrote {'CSV' if args.reverse else 'Ansible matrix'} to {output_path}")


if __name__ == "__main__":
    main()
