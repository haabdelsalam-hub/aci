#!/usr/bin/env bash
set -euo pipefail

export ANSIBLE_LOCAL_TEMP="${ANSIBLE_LOCAL_TEMP:-/tmp/aci-ansible-local}"
mkdir -p "$ANSIBLE_LOCAL_TEMP"

exec ansible-playbook master_migrate.yml -e "matrix_file=prod_matrix.yml env=prod" --tags "core,physical,static"
