# Sourced by sdk/bin/obsd-*: resolve the interpreter for obsd_toolchain.py.
# Order: $OBSD_PYTHON (exported by build_ports.py / make), else the newest
# python3.1x on PATH, else python3. Never searches outside PATH.
if [ -z "${OBSD_PYTHON:-}" ]; then
	for _obsd_py in python3.14 python3.13 python3.12 python3.11 python3; do
		if command -v "$_obsd_py" >/dev/null 2>&1; then
			OBSD_PYTHON=$_obsd_py
			break
		fi
	done
	unset _obsd_py
fi
: "${OBSD_PYTHON:=python3}"
export OBSD_PYTHON
