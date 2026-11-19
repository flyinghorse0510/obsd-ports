#!/usr/bin/env bash
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
bash "$here/audit_tree_layout.sh"
bash "$here/audit_make_hierarchy.sh"
bash "$here/audit_matrix_seams.sh"
bash "$here/audit_vendor_clean.sh"
printf 'all obsd-ports audits: PASS\n'
