#!/usr/bin/env python3
"""
run_check.py -- Top-level `make check` driver for `obsd-ports`.

Supports both:
  - `COMPAT_PAL=emscripten` (`emulate`): WASM64 SDK smoke check, `tests/test_sdk.py`,
    `tests/run_wasm_ports_tests.py`, and Wave-2/Wave-3 WASM64 port suites.
  - `COMPAT_PAL=darwin` (`translate` for `macosx`, `emulate` for `iphonesimulator`
    & `iphoneos`): Darwin SDK smoke check (`obsd-cc`, `obsd-c++`, `obsd-pkg-config`)
    and `tests/run_darwin_ports_tests.py` (Mach-O/ABI/`x18`/App-Store-policy audit,
    static-library C/C++17 link checks, `emulate` table co-generation check, and
    live OpenBSD VFS execution across all 53 ports on `translate/darwin-macosx`).
"""
from __future__ import annotations

import argparse
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
from typing import Optional

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools/config"))
import obsd_versions  # noqa: E402  (release axis from config/versions/index.tsv)
import obsd_env  # noqa: E402  (EMSDK_PYTHON pinning)


def find_node_dir(obsd_root: pathlib.Path) -> Optional[pathlib.Path]:
    emsdk_nodes = sorted((obsd_root / "deps/emsdk/node").rglob("bin/node"))
    if emsdk_nodes:
        return emsdk_nodes[-1].parent
    w = shutil.which("node")
    if w:
        return pathlib.Path(w).resolve().parent
    return None


def resolve_sdk(pal: str, backend: str, cli_sdk: str) -> str:
    if pal != "darwin":
        return ""
    sdk = (cli_sdk or os.environ.get("COMPAT_SDK", "")).strip()
    if not sdk:
        sdk = "macosx" if backend == "translate" else "iphonesimulator"
    return sdk


def verify_emscripten_sdk_smoke(openbsd_version: str, obsd_root: pathlib.Path) -> None:
    obsd_cc = REPO_ROOT / "sdk/bin/obsd-cc"
    obsd_pc = REPO_ROOT / "sdk/bin/obsd-pkg-config"
    wasm_obj_tool = obsd_root / "tools/build/personalities/openbsd/backends/emulate/wasm_object_tool.py"

    env = dict(os.environ)
    env["OPENBSD_VERSION"] = openbsd_version
    env["COMPAT_BACKEND"] = "emulate"
    env["COMPAT_PAL"] = "emscripten"
    env["LIBOBSDCOMPAT_ROOT"] = str(obsd_root)
    env["OBSD_PYTHON"] = sys.executable

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
    print(f"[check/{openbsd_version}/emulate/emscripten] SDK cross-compiler & applet localization check: OK")


def verify_darwin_sdk_smoke(openbsd_version: str, backend: str, sdk: str, obsd_root: pathlib.Path) -> None:
    obsd_cc = REPO_ROOT / "sdk/bin/obsd-cc"
    obsd_cxx = REPO_ROOT / "sdk/bin/obsd-c++"
    obsd_pc = REPO_ROOT / "sdk/bin/obsd-pkg-config"

    env = dict(os.environ)
    env["OPENBSD_VERSION"] = openbsd_version
    env["COMPAT_BACKEND"] = backend
    env["COMPAT_PAL"] = "darwin"
    env["COMPAT_SDK"] = sdk
    env["LIBOBSDCOMPAT_ROOT"] = str(obsd_root)
    env["OBSD_PYTHON"] = sys.executable

    with tempfile.TemporaryDirectory(prefix=f"obsd-darwin-sdk-check-{sdk}-") as td:
        tp = pathlib.Path(td)
        probe_c = tp / "probe.c"
        probe_o = tp / "probe_c"
        probe_c.write_text(
            "#include <sys/param.h>\n"
            "#include <stdio.h>\n"
            "#include <stdlib.h>\n"
            "#include <zlib.h>\n"
            "#include <curses.h>\n"
            "#include <openssl/ssl.h>\n"
            "int main(int argc, char **argv) {\n"
            "  (void)argv;\n"
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
        if backend == "translate":
            rc = subprocess.run([str(probe_o)]).returncode
            if rc != 0:
                raise AssertionError(f"Darwin translate C SDK probe exited with {rc}")

        probe_cpp = tp / "probe.cpp"
        probe_cxx_o = tp / "probe_cxx"
        probe_cpp.write_text(
            "#include <stdexcept>\n"
            "#include <string>\n"
            "#include <vector>\n"
            "static thread_local int tls_v = 41;\n"
            "int main(void) {\n"
            "  try { throw std::runtime_error(\"ok\"); }\n"
            "  catch (const std::exception &e) { return (++tls_v == 42 && e.what()[0] == 'o') ? 0 : 2; }\n"
            "  return 1;\n"
            "}\n",
            encoding="utf-8",
        )
        subprocess.run([str(obsd_cxx), "-std=c++17", "-O2", str(probe_cpp), "-o", str(probe_cxx_o)], env=env, check=True)
        if backend == "translate":
            rc2 = subprocess.run([str(probe_cxx_o)]).returncode
            if rc2 != 0:
                raise AssertionError(f"Darwin translate C++17 SDK probe exited with {rc2}")

        subprocess.run([str(obsd_pc), "--libs", "openssl", "zlib", "ncursesw"], env=env, check=True, stdout=subprocess.DEVNULL)
    print(f"[check/{openbsd_version}/{backend}/darwin-{sdk}] Darwin C & C++17 SDK cross-compiler check: OK")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--openbsd-version", default=obsd_versions.env_or_default_version())
    ap.add_argument("--backend", default="emulate")
    ap.add_argument("--pal", default="emscripten")
    ap.add_argument("--sdk", default="")
    ap.add_argument("--libobsdcompat-root", required=True)
    ap.add_argument("--port", default="")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 8)
    args = ap.parse_args()
    obsd_versions.require_verified(args.openbsd_version)

    obsd_root = pathlib.Path(args.libobsdcompat_root).resolve()
    sdk = resolve_sdk(args.pal, args.backend, args.sdk)

    rc_axis = subprocess.run(
        [sys.executable, "-I", str(REPO_ROOT / "tests/test_release_axis.py"), "--libobsdcompat-root", str(obsd_root)],
        cwd=str(REPO_ROOT),
    ).returncode
    if rc_axis != 0:
        return rc_axis

    if args.pal == "darwin":
        verify_darwin_sdk_smoke(args.openbsd_version, args.backend, sdk, obsd_root)
        darwin_suite = REPO_ROOT / "tests/run_darwin_ports_tests.py"
        cmd = [
            sys.executable,
            "-I",
            str(darwin_suite),
            "--openbsd-version",
            args.openbsd_version,
            "--backend",
            args.backend,
            "--sdk",
            sdk,
            "--libobsdcompat-root",
            str(obsd_root),
            "--jobs",
            str(args.jobs),
        ]
        if args.port:
            cmd.extend(["--port", args.port])
        return subprocess.run(cmd, cwd=str(REPO_ROOT)).returncode

    obsd_env.ensure_emsdk_python(args.libobsdcompat_root)
    lane_dir = REPO_ROOT / "build/openbsd" / args.openbsd_version / args.backend / args.pal

    verify_emscripten_sdk_smoke(args.openbsd_version, obsd_root)

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
    env["OBSD_PYTHON"] = sys.executable

    path_parts = [str(REPO_ROOT / "sdk/bin")]
    node_dir = find_node_dir(obsd_root)
    if node_dir:
        path_parts.append(str(node_dir))
        env["EMSDK_NODE"] = str(node_dir / "node")
    path_parts.append(env.get("PATH", "/usr/bin:/bin"))
    env["PATH"] = ":".join(path_parts)

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

    rc_main = subprocess.run(cmd, cwd=str(REPO_ROOT), env=env).returncode
    if rc_main != 0:
        return rc_main

    if not args.port:
        wave2_suites = [
            "tests/wave2_dev.py",
            "tests/wave2_search_gnu.py",
            "tests/wave2_net_arch.py",
            "tests/wave2_sys_tui.py",
            "tests/wave3_sysmon.py",
        ]
        for rel_suite in wave2_suites:
            sp_path = REPO_ROOT / rel_suite
            if not sp_path.is_file():
                continue
            rc_w2 = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(sp_path),
                    "--openbsd-version",
                    args.openbsd_version,
                    "--libobsdcompat-root",
                    str(obsd_root),
                ],
                cwd=str(REPO_ROOT),
                env=env,
            ).returncode
            if rc_w2 != 0:
                return rc_w2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
