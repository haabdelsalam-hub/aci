#!/usr/bin/env bash
set -euo pipefail

export ANSIBLE_LOCAL_TEMP="${ANSIBLE_LOCAL_TEMP:-/tmp/aci-ansible-local}"
mkdir -p "$ANSIBLE_LOCAL_TEMP"

exec ansible-playbook configure_static_access_ports.yml
