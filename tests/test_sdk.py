#!/usr/bin/env python3
"""
tests/test_sdk.py -- Unit & WASM64 Guest Integration Tests for `obsd-ports` SDK:
  1. Pure-Python multi-member LZIP v1 (`.tar.lz`) extraction & CRC32 verification
     in `tools/build_ports.py:extract_archive()`.
  2. Multi-call symlink alias discovery (`discover_symlink_aliases_in`) in
     `targets/emulate/emscripten/package_wasm.py`.
  3. WASM64 C++17 (`sdk/bin/obsd-c++`) compilation (`#include_next` interop with
     OpenBSD `include-root-<ver>`, static `libc++` + `libc++abi` linkage,
     per-exec `WASM_INIT_FUNCS` static constructors, native Wasm EH `try`/`catch`
     plus `-fno-exceptions`), `wasm_object_tool.py localize-applet`, and live
     execution inside `merge_wasm_guest.py run-guest` under `MALLOC_OPTIONS=JJ`.
"""
from __future__ import annotations

import argparse
import io
import lzma
import os
import pathlib
import struct
import subprocess
import sys
import tarfile
import tempfile
import zlib
from typing import List

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "tools"))
if str(REPO_ROOT / "targets/emulate/emscripten") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "targets/emulate/emscripten"))

import build_ports as bp  # type: ignore
import package_wasm as pw  # type: ignore


def resolve_obsd_root(cli_val: str = "") -> pathlib.Path:
    if cli_val:
        return pathlib.Path(cli_val).resolve()
    env_val = os.environ.get("LIBOBSDCOMPAT_ROOT", "").strip()
    if env_val:
        return pathlib.Path(env_val).resolve()
    out = subprocess.check_output(
        ["sh", str(REPO_ROOT / "tools/config/locate-libobsdcompat.sh")],
        text=True,
    ).strip()
    return pathlib.Path(out).resolve()


def encode_lzip_member(payload: bytes, dict_exp: int = 16) -> bytes:
    dict_size = 1 << dict_exp
    header = b"LZIP\x01" + bytes([dict_exp & 0x1F])
    comp = lzma.LZMACompressor(
        format=lzma.FORMAT_RAW,
        filters=[{"id": lzma.FILTER_LZMA1, "dict_size": dict_size, "lc": 3, "lp": 0, "pb": 2}],
    )
    body = comp.compress(payload) + comp.flush()
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    member_size = len(header) + len(body) + 20
    trailer = struct.pack("<IQQ", crc, len(payload), member_size)
    return header + body + trailer


def test_lzip_extraction() -> None:
    with tempfile.TemporaryDirectory(prefix="obsd-test-lzip-") as td:
        tp = pathlib.Path(td)
        tar_buf = io.BytesIO()
        with tarfile.open(fileobj=tar_buf, mode="w") as tf:
            for name, content in (
                ("pkg-1.0/README.txt", b"Pure Python LZIP v1 multi-member test\n" * 64),
                ("pkg-1.0/src/hello.c", b"int main(void) { return 0; }\n"),
            ):
                ti = tarfile.TarInfo(name)
                ti.size = len(content)
                ti.mode = 0o644
                tf.addfile(ti, io.BytesIO(content))

        raw_tar = tar_buf.getvalue()
        mid = len(raw_tar) // 2
        # Multi-member LZIP stream (2 members + 8 bytes of trailing zero padding)
        lz_bytes = encode_lzip_member(raw_tar[:mid], 15) + encode_lzip_member(raw_tar[mid:], 16) + (b"\x00" * 8)
        lz_path = tp / "multi.tar.lz"
        lz_path.write_bytes(lz_bytes)

        out_dir = tp / "extracted"
        out_dir.mkdir()
        bp.extract_archive(lz_path, out_dir)
        assert (out_dir / "pkg-1.0/README.txt").read_bytes() == b"Pure Python LZIP v1 multi-member test\n" * 64
        assert (out_dir / "pkg-1.0/src/hello.c").read_bytes() == b"int main(void) { return 0; }\n"

        # Verify gmake's real make-4.4.1.tar.lz when cached
        gmake_lz = REPO_ROOT / ".cache/distfiles/make-4.4.1.tar.lz"
        if gmake_lz.is_file():
            gm_dir = tp / "gmake"
            gm_dir.mkdir()
            bp.extract_archive(gmake_lz, gm_dir)
            assert (gm_dir / "make-4.4.1/configure").is_file()

    print("[SDK-TEST] pure-Python multi-member .tar.lz extraction: PASS")


def test_symlink_alias_discovery(openbsd_version: str, obsd_root: pathlib.Path) -> None:
    obsd_cc = REPO_ROOT / "sdk/bin/obsd-cc"
    env = dict(os.environ)
    env["OPENBSD_VERSION"] = openbsd_version
    env["LIBOBSDCOMPAT_ROOT"] = str(obsd_root)

    with tempfile.TemporaryDirectory(prefix="obsd-test-symlinks-") as td:
        tp = pathlib.Path(td)
        lane_dir = tp / "lane"
        stage_bin = lane_dir / "stage/usr/local/bin"
        stage_bin.mkdir(parents=True)

        mc_c = tp / "mc.c"
        mc_c.write_text("int main(int argc, char **argv) { (void)argv; return argc - 1; }\n", encoding="utf-8")
        subprocess.run([str(obsd_cc), str(mc_c), "-o", str(stage_bin / "gcoreutils")], env=env, check=True)

        os.symlink("gcoreutils", stage_bin / "gtrue")
        os.symlink("/usr/local/bin/gcoreutils", stage_bin / "gfalse")
        (stage_bin / "unrelated_script").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")

        records = [
            {
                "port": "sysutils/mock-multicall",
                "pkgname": "mock-multicall-1.0",
                "applets": [
                    {
                        "sym": "gcoreutils",
                        "binary": "/usr/local/bin/gcoreutils",
                        "paths": ["/usr/local/bin/gcoreutils"],
                        "discover_symlink_aliases_in": ["/usr/local/bin"],
                    }
                ],
            }
        ]
        tsv_rows, guest_paths = pw.localize_port_applets(
            obsd_root=obsd_root,
            openbsd_version=openbsd_version,
            lane_dir=lane_dir,
            stage_dir=lane_dir / "stage",
            records=records,
        )
        expected = {"/usr/local/bin/gcoreutils", "/usr/local/bin/gtrue", "/usr/local/bin/gfalse"}
        assert guest_paths == expected, f"expected {expected}, got {guest_paths}"
        assert len(tsv_rows) == 3

    print(f"[SDK-TEST] [{openbsd_version}] package_wasm discover_symlink_aliases_in: PASS")


CXX17_PROBE_SRC = r'''
#include <cstdlib>
#include <cmath>
#include <cwchar>
#include <cstring>
#include <sys/utsname.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

extern "C" int cxx_noexcept_helper(int x);

namespace {
struct CodecRegistry {
    std::vector<std::string> codecs;
    CodecRegistry() {
        codecs.push_back("lzma2");
        codecs.push_back("zstd");
        codecs.push_back("bzip2");
        std::sort(codecs.begin(), codecs.end());
    }
};

CodecRegistry g_registry;
} // namespace

struct RaiiTracker {
    int &counter;
    explicit RaiiTracker(int &c) : counter(c) { counter += 10; }
    ~RaiiTracker() { counter += 5; }
};

int main(int argc, char **argv) {
    struct utsname uts;
    if (uname(&uts) != 0) {
        std::cerr << "uname failed\n";
        return 2;
    }

    std::mutex mtx;
    std::lock_guard<std::mutex> lk(mtx);

    int raii_state = 0;
    std::string caught_msg = "NONE";
    try {
        RaiiTracker guard(raii_state);
        if (argc >= 1) {
            throw std::runtime_error("EH_UNWIND_OK");
        }
    } catch (const std::exception &ex) {
        caught_msg = ex.what();
    }

    double hyp = std::hypot(3.0, 4.0);
    size_t wlen = std::wcslen(L"OpenBSD");

    std::filesystem::path dir = "/tmp/cxx17_sdk_probe";
    std::filesystem::create_directories(dir);
    std::filesystem::path fpath = dir / "note.txt";
    {
        std::ofstream ofs(fpath);
        ofs << "ptr=" << sizeof(void *) << ";noexc=" << cxx_noexcept_helper(20);
    }
    std::string file_data;
    {
        std::ifstream ifs(fpath);
        std::getline(ifs, file_data);
    }

    std::regex re("^([A-Za-z]+)_([A-Z]+)_([A-Z]+)$");
    std::smatch m;
    bool rgx_ok = std::regex_match(caught_msg, m, re);

    std::cout << "OS=" << uts.sysname << "-" << uts.release
              << "|CTOR=" << g_registry.codecs.size() << ":" << g_registry.codecs[0]
              << "|RAII=" << raii_state
              << "|EH=" << (rgx_ok ? m[2].str() : "BAD")
              << "|HYP=" << static_cast<int>(hyp)
              << "|WLEN=" << wlen
              << "|" << file_data
              << "|ARG=" << (argc > 1 ? argv[1] : "none")
              << std::endl;
    return 0;
}
'''

CXX17_NOEXCEPT_HELPER_SRC = r'''
#include <numeric>
#include <vector>

extern "C" int cxx_noexcept_helper(int x) {
    std::vector<int> vals = {1, 2, 3, 4, x};
    return std::accumulate(vals.begin(), vals.end(), 0);
}
'''


def test_cxx17_build_localize_and_run(openbsd_version: str, obsd_root: pathlib.Path) -> None:
    obsd_cxx = REPO_ROOT / "sdk/bin/obsd-c++"
    wasm_obj_tool = obsd_root / "tools/build/personalities/openbsd/backends/emulate/wasm_object_tool.py"
    merge_guest_py = REPO_ROOT / "targets/emulate/emscripten/merge_wasm_guest.py"

    env = dict(os.environ)
    env["OPENBSD_VERSION"] = openbsd_version
    env["LIBOBSDCOMPAT_ROOT"] = str(obsd_root)

    with tempfile.TemporaryDirectory(prefix=f"obsd-test-cxx17-{openbsd_version}-") as td:
        tp = pathlib.Path(td)
        lane_dir = tp / "lane"
        (lane_dir / "applets").mkdir(parents=True)
        (lane_dir / "sysroot/usr/local").mkdir(parents=True)

        helper_cpp = tp / "helper_noexcept.cpp"
        helper_o = tp / "helper_noexcept.o"
        helper_cpp.write_text(CXX17_NOEXCEPT_HELPER_SRC, encoding="utf-8")
        subprocess.run(
            [str(obsd_cxx), "-std=c++17", "-fno-exceptions", "-c", str(helper_cpp), "-o", str(helper_o)],
            env=env,
            check=True,
        )

        probe_cpp = tp / "probe_cxx17.cpp"
        probe_bin = tp / "probe_cxx17"
        probe_loc = lane_dir / "applets/cxx17_probe.o"
        probe_cpp.write_text(CXX17_PROBE_SRC, encoding="utf-8")
        subprocess.run(
            [str(obsd_cxx), "-std=c++17", "-Wall", "-Wextra", str(probe_cpp), str(helper_o), "-o", str(probe_bin)],
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
                "cxx17_probe",
                "--entry-symbol",
                "__main_argc_argv",
                "-i",
                str(probe_bin),
                "-o",
                str(probe_loc),
            ],
            env=env,
            check=True,
        )

        (lane_dir / "ports-applets.tsv").write_text(
            "cxx17_probe\t/usr/local/bin/cxx17_probe\tobsd_applet_cxx17_probe_main\tapplets/cxx17_probe.o\n",
            encoding="utf-8",
        )

        # Execute TWICE under MALLOC_OPTIONS=JJ inside the WASM64 OpenBSD kernel to verify
        # per-exec static constructors (`WASM_INIT_FUNCS`), Wasm EH unwinding, and 64-bit ABI.
        proc = subprocess.run(
            [
                sys.executable,
                "-I",
                str(merge_guest_py),
                "run-guest",
                "--libobsdcompat-root",
                str(obsd_root),
                "--openbsd-version",
                openbsd_version,
                "--ports-lane-dir",
                str(lane_dir),
                "--cmd",
                "MALLOC_OPTIONS=JJ /usr/local/bin/cxx17_probe run1 && MALLOC_OPTIONS=JJ /usr/local/bin/cxx17_probe run2",
            ],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if proc.returncode != 0:
            raise AssertionError(f"run-guest failed (rc={proc.returncode}):\n{proc.stdout}")
        out_lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip().startswith("OS=")]
        exp_base = f"OS=OpenBSD-{openbsd_version}|CTOR=3:bzip2|RAII=15|EH=UNWIND|HYP=5|WLEN=7|ptr=8;noexc=30"
        expected_lines = [f"{exp_base}|ARG=run1", f"{exp_base}|ARG=run2"]
        if out_lines != expected_lines:
            raise AssertionError(f"unexpected C++17 guest output:\ngot: {out_lines}\nfull:\n{proc.stdout}")

    print(f"[SDK-TEST] [{openbsd_version}] obsd-c++ C++17 build + localize + WASM64 guest execution: PASS")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--openbsd-version", default=os.environ.get("OPENBSD_VERSION", "all"))
    ap.add_argument("--libobsdcompat-root", default="")
    args = ap.parse_args()

    obsd_root = resolve_obsd_root(args.libobsdcompat_root)
    target = args.openbsd_version.strip()
    versions: List[str] = ["7.8", "7.9"] if target in ("", "all") else [v.strip() for v in target.split(",") if v.strip()]

    test_lzip_extraction()
    for ver in versions:
        test_symlink_alias_discovery(ver, obsd_root)
        test_cxx17_build_localize_and_run(ver, obsd_root)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
