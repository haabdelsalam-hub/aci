#!/usr/bin/env bash
set -euo pipefail

export ANSIBLE_LOCAL_TEMP="${ANSIBLE_LOCAL_TEMP:-/tmp/aci-ansible-local}"
mkdir -p "$ANSIBLE_LOCAL_TEMP"

exec ansible-playbook master_migrate.yml -e "matrix_file=dmz_matrix.yml env=dmz" --tags "core,physical,static,nutanix,vmware"
