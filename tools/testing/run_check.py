#!/usr/bin/env python3
"""
run_check.py -- Top-level `make check` driver for `obsd-ports`.

1. Verifies the Guest Cross-Compilation SDK (`obsd-cc`, `obsd-pkg-config`,
   symbol closure checking, and `wasm_object_tool.py localize-applet`) on the
   selected `OPENBSD_VERSION`.
2. When `tests/run_wasm_ports_tests.py` is present (owned by `@ports-pack`),
   executes the full WASM64 port test suite for `OPENBSD_VERSION` with hermetic
   `NODE`, `LIBOBSDCOMPAT_ROOT`, `OBSD_PORTS_ROOT`, and `OBSD_LANE_DIR` wired.
"""
from __future__ import annotations

import argparse
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


def find_node_dir(obsd_root: pathlib.Path) -> Optional[pathlib.Path]:
    emsdk_nodes = sorted((obsd_root / "deps/emsdk/node").rglob("bin/node"))
    if emsdk_nodes:
        return emsdk_nodes[-1].parent
    w = shutil.which("node")
    if w:
        return pathlib.Path(w).resolve().parent
    return None


def verify_sdk_smoke(openbsd_version: str, obsd_root: pathlib.Path) -> None:
    obsd_cc = REPO_ROOT / "sdk/bin/obsd-cc"
    obsd_pc = REPO_ROOT / "sdk/bin/obsd-pkg-config"
    wasm_obj_tool = obsd_root / "tools/build/personalities/openbsd/backends/emulate/wasm_object_tool.py"

    env = dict(os.environ)
    env["OPENBSD_VERSION"] = openbsd_version
    env["LIBOBSDCOMPAT_ROOT"] = str(obsd_root)

    with tempfile.TemporaryDirectory(prefix="obsd-sdk-check-") as td:
        tp = pathlib.Path(td)
        probe_c = tp / "probe.c"
        probe_o = tp / "probe"
        probe_loc = tp / "probe.loc.o"
        probe_c.write_text(
            "#include <sys/param.h>\n"
            "#include <stdio.h>\n"
            "#include <stdlib.h>\n"
            "#include <zlib.h>\n"
            "#include <curses.h>\n"
            "#include <openssl/ssl.h>\n"
            "int main(int argc, char **argv) {\n"
            "  char buf[32];\n"
            "  (void)argv;\n"
            "  snprintf(buf, sizeof(buf), \"%d\", argc);\n"
            "  printf(\"%s\\n\", buf);\n"
            "  fprintf(stderr, \"%d\\n\", argc);\n"
            "  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());\n"
            "  return (ctx != NULL && zlibVersion() != NULL) ? (argc - 1) : 1;\n"
            "}\n",
            encoding="utf-8",
        )
        subprocess.run(
            [str(obsd_cc), str(probe_c), "-lssl", "-lcrypto", "-lz", "-lcurses", "-o", str(probe_o)],
            env=env,
            check=True,
        )
        subprocess.run(
            [
                sys.executable,
                "-I",
                str(wasm_obj_tool),
                "localize-applet",
                "--applet-sym",
                "sdk_probe",
                "--entry-symbol",
                "__main_argc_argv",
                "-i",
                str(probe_o),
                "-o",
                str(probe_loc),
            ],
            env=env,
            check=True,
        )
        subprocess.run([str(obsd_pc), "--libs", "openssl", "zlib", "ncursesw"], env=env, check=True, stdout=subprocess.DEVNULL)
    print(f"[check/{openbsd_version}] SDK cross-compiler & applet localization check: OK")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--openbsd-version", default="7.9")
    ap.add_argument("--backend", default="emulate")
    ap.add_argument("--pal", default="emscripten")
    ap.add_argument("--libobsdcompat-root", required=True)
    ap.add_argument("--port", default="")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 8)
    args = ap.parse_args()

    obsd_root = pathlib.Path(args.libobsdcompat_root).resolve()
    lane_dir = REPO_ROOT / "build/openbsd" / args.openbsd_version / args.backend / args.pal

    verify_sdk_smoke(args.openbsd_version, obsd_root)

    test_sdk_py = REPO_ROOT / "tests/test_sdk.py"
    if test_sdk_py.is_file():
        rc_sdk = subprocess.run(
            [
                sys.executable,
                "-I",
                str(test_sdk_py),
                "--openbsd-version",
                args.openbsd_version,
                "--libobsdcompat-root",
                str(obsd_root),
            ],
            cwd=str(REPO_ROOT),
        ).returncode
        if rc_sdk != 0:
            return rc_sdk

    suite_py = REPO_ROOT / "tests/run_wasm_ports_tests.py"
    if not suite_py.is_file():
        print(f"[check/{args.openbsd_version}] tests/run_wasm_ports_tests.py not yet present; SDK check passed")
        return 0

    env = dict(os.environ)
    env["OBSD_PORTS_ROOT"] = str(REPO_ROOT)
    env["LIBOBSDCOMPAT_ROOT"] = str(obsd_root)
    env["OPENBSD_VERSION"] = args.openbsd_version
    env["COMPAT_BACKEND"] = args.backend
    env["COMPAT_PAL"] = args.pal
    env["OBSD_LANE_DIR"] = str(lane_dir)

    path_parts = [str(REPO_ROOT / "sdk/bin")]
    node_dir = find_node_dir(obsd_root)
    if node_dir:
        path_parts.append(str(node_dir))
        env["EMSDK_NODE"] = str(node_dir / "node")
    path_parts.append(env.get("PATH", "/usr/bin:/bin"))
    env["PATH"] = ":".join(path_parts)

    # Inspect supported CLI arguments of `tests/run_wasm_ports_tests.py` so both
    # `--openbsd-version` and `--version` / `--release` conventions work seamlessly.
    help_proc = subprocess.run(
        [sys.executable, "-I", str(suite_py), "--help"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    help_txt = help_proc.stdout or ""

    cmd = [sys.executable, "-I", str(suite_py)]
    if "--openbsd-version" in help_txt:
        cmd.extend(["--openbsd-version", args.openbsd_version])
    elif "--version" in help_txt:
        cmd.extend(["--version", args.openbsd_version])
    elif "--release" in help_txt:
        cmd.extend(["--release", args.openbsd_version])

    if "--libobsdcompat-root" in help_txt:
        cmd.extend(["--libobsdcompat-root", str(obsd_root)])
    if "--jobs" in help_txt:
        cmd.extend(["--jobs", str(args.jobs)])
    if args.port and "--port" in help_txt:
        cmd.extend(["--port", args.port])

    return subprocess.run(cmd, cwd=str(REPO_ROOT), env=env).returncode


if __name__ == "__main__":
    raise SystemExit(main())
