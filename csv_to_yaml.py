#!/usr/bin/env python3
"""Convert a complete EPG CSV inventory into an Ansible tenant matrix."""

import argparse
import csv
import json
from pathlib import Path

import yaml

REQUIRED_COLUMNS = {
    "tenant_name", "epg_name", "encap_id", "name", "ap_name", "vrf_name",
    "vmware_domains", "nutanix_domains", "physical_domains", "static_bindings",
}
LIST_COLUMNS = ("vmware_domains", "nutanix_domains", "physical_domains", "static_bindings")
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


def convert(csv_path, yaml_path):
    with csv_path.open(newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        missing = REQUIRED_COLUMNS - set(reader.fieldnames or [])
        if missing:
            raise ValueError("CSV is missing required columns: " + ", ".join(sorted(missing)))

        rows = []
        tenants = set()
        for line_number, raw in enumerate(reader, start=2):
            if not any((value or "").strip() for value in raw.values()):
                continue
            tenant = (raw["tenant_name"] or "").strip()
            if not tenant:
                raise ValueError(f"line {line_number}: tenant_name is required")
            tenants.add(tenant)
            try:
                epg_id = int(raw["epg_name"])
                encap_id = int(raw["encap_id"])
            except (TypeError, ValueError) as exc:
                raise ValueError(f"line {line_number}: epg_name and encap_id must be integers") from exc

            row = {
                "epg_name": epg_id,
                "encap_id": encap_id,
                "name": (raw["name"] or "").strip(),
                "ap_name": (raw["ap_name"] or "").strip(),
                "vrf_name": (raw["vrf_name"] or "").strip(),
            }
            for column in LIST_COLUMNS:
                row[column] = parse_json_cell(raw[column], column, line_number)
            bindings = row.pop("static_bindings")

            if not all(row[key] for key in ("name", "ap_name", "vrf_name")):
                raise ValueError(f"line {line_number}: name, ap_name, and vrf_name are required")
            if not bindings:
                raise ValueError(f"line {line_number}: EPG has no static binding")
            for binding in bindings:
                if not isinstance(binding, dict):
                    raise ValueError(f"line {line_number}: each static binding must be a JSON object")
                if not REQUIRED_BINDING_FIELDS.issubset(binding):
                    missing_fields = REQUIRED_BINDING_FIELDS - set(binding)
                    raise ValueError(f"line {line_number}: static binding is missing: {', '.join(sorted(missing_fields))}")
                if binding["encap_id"] != encap_id:
                    raise ValueError(f"line {line_number}: each static binding must use this row's encap_id")
            row["static_bindings"] = bindings
            rows.append(row)

    if not rows:
        raise ValueError("CSV contains no EPG rows")
    if len(tenants) != 1:
        raise ValueError("CSV must contain rows for exactly one tenant")

    matrix = {"tenant_name": tenants.pop(), "vlan_migration_list": rows}
    with yaml_path.open("w", encoding="utf-8") as destination:
        yaml.dump(matrix, destination, Dumper=MatrixDumper, sort_keys=False, allow_unicode=True)


STATIC_COLUMNS = (
    "static_aep", "static_physical_domains", "static_vlan_pool",
    "static_interface_policy_defaults", "static_leaf_profiles", "static_vpc_trunks",
    "static_vpc_access_ports", "static_single_access_policy_group",
    "static_single_access_ports", "static_interface_policy_groups", "static_interface_configs",
)
STATIC_OPTIONAL_COLUMNS = {"static_interface_policy_groups", "static_interface_configs"}


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
    for key in ("static_physical_domains", "static_leaf_profiles", "static_vpc_trunks", "static_vpc_access_ports", "static_single_access_ports", "static_interface_policy_groups", "static_interface_configs"):
        if not isinstance(matrix[key], list):
            raise ValueError(f"{key} must be a JSON array")
    with yaml_path.open("w", encoding="utf-8") as destination:
        yaml.dump(matrix, destination, Dumper=MatrixDumper, sort_keys=False, allow_unicode=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    default_dir = Path(__file__).resolve().parent
    parser.add_argument("--type", choices=("tenant", "static_access"), default="tenant", help="Matrix schema to generate")
    parser.add_argument("input", nargs="?", type=Path, default=default_dir / "input.csv")
    parser.add_argument("output", nargs="?", type=Path, default=default_dir / "output.yaml")
    args = parser.parse_args()
    try:
        (convert_static_access if args.type == "static_access" else convert)(args.input, args.output)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(f"Wrote Ansible matrix to {args.output}")


if __name__ == "__main__":
    main()
