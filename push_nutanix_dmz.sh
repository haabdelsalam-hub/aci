# Push the core networks, VMware clusters, Nutanix infrastructure, and Physical hooks all at once
ansible-playbook master_migrate.yml -e "matrix_file=dmz_matrix.yml" --tags "nutanix"

