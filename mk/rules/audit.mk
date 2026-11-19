.PHONY: audit audit-vendor audit-layout audit-make audit-matrix

audit:
	bash "$(TOOLS_ROOT)/audit/run_all_audits.sh"

audit-vendor:
	bash "$(TOOLS_ROOT)/audit/audit_vendor_clean.sh"

audit-layout:
	bash "$(TOOLS_ROOT)/audit/audit_tree_layout.sh"

audit-make:
	bash "$(TOOLS_ROOT)/audit/audit_make_hierarchy.sh"

audit-matrix:
	bash "$(TOOLS_ROOT)/audit/audit_matrix_seams.sh"
