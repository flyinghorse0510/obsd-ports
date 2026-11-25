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
sys.path.insert(0, str(REPO_ROOT / "tools/config"))
import obsd_versions  # noqa: E402  (release axis from config/versions/index.tsv)
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


CHUNK_OREALLOC_PROBE_SRC = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Regression test for adjacent 16 MiB WASM backing-chunk boundary coalescing:
 * Allocates >20 MiB across multiple 16 MiB backing chunks while repeatedly
 * doubling multi-page allocations (4 KiB -> 8 KiB -> ... -> 128 KiB) via
 * realloc() so OpenBSD omalloc's orealloc() attempts in-place MAP_FIXED |
 * __MAP_NOREPLACE extensions at every chunk tail, then verifies data integrity
 * and munmap() via free() under MALLOC_OPTIONS=JJ.
 */
#define SLOT_COUNT 224

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    uint8_t *slots[SLOT_COUNT];
    size_t sizes[SLOT_COUNT];

    for (int i = 0; i < SLOT_COUNT; i++) {
        sizes[i] = 4096U;
        slots[i] = (uint8_t *)malloc(sizes[i]);
        if (!slots[i]) {
            fprintf(stderr, "malloc slot %d failed\n", i);
            return 2;
        }
        memset(slots[i], (uint8_t)((i * 37 + 11) & 0xff), sizes[i]);
    }

    for (size_t target_sz = 8192U; target_sz <= 131072U; target_sz *= 2U) {
        for (int i = 0; i < SLOT_COUNT; i++) {
            uint8_t expected = (uint8_t)((i * 37 + 11) & 0xff);
            uint8_t *grown = (uint8_t *)realloc(slots[i], target_sz);
            if (!grown) {
                fprintf(stderr, "realloc slot %d to %zu failed\n", i, target_sz);
                return 3;
            }
            if (grown[0] != expected || grown[sizes[i] - 1] != expected) {
                fprintf(stderr, "realloc data corruption at slot %d\n", i);
                return 4;
            }
            memset(grown + sizes[i], expected, target_sz - sizes[i]);
            slots[i] = grown;
            sizes[i] = target_sz;
        }
    }

    size_t total_bytes = 0;
    for (int i = 0; i < SLOT_COUNT; i++) {
        uint8_t expected = (uint8_t)((i * 37 + 11) & 0xff);
        if (slots[i][0] != expected || slots[i][sizes[i] - 1] != expected) {
            fprintf(stderr, "final verify failed at slot %d\n", i);
            return 5;
        }
        total_bytes += sizes[i];
        free(slots[i]);
    }

    printf("CHUNK_OREALLOC_OK=%zu\n", total_bytes);
    return 0;
}
'''


def test_chunk_boundary_orealloc_guard(openbsd_version: str, obsd_root: pathlib.Path) -> None:
    obsd_cc = REPO_ROOT / "sdk/bin/obsd-cc"
    wasm_obj_tool = obsd_root / "tools/build/personalities/openbsd/backends/emulate/wasm_object_tool.py"
    merge_guest_py = REPO_ROOT / "targets/emulate/emscripten/merge_wasm_guest.py"

    env = dict(os.environ)
    env["OPENBSD_VERSION"] = openbsd_version
    env["LIBOBSDCOMPAT_ROOT"] = str(obsd_root)

    with tempfile.TemporaryDirectory(prefix=f"obsd-test-orealloc-{openbsd_version}-") as td:
        tp = pathlib.Path(td)
        lane_dir = tp / "lane"
        (lane_dir / "applets").mkdir(parents=True)
        (lane_dir / "sysroot/usr/local").mkdir(parents=True)

        probe_c = tp / "probe_orealloc.c"
        probe_bin = tp / "probe_orealloc"
        probe_loc = lane_dir / "applets/orealloc_probe.o"
        probe_c.write_text(CHUNK_OREALLOC_PROBE_SRC, encoding="utf-8")
        subprocess.run(
            [str(obsd_cc), "-O2", "-Wall", "-Wextra", str(probe_c), "-o", str(probe_bin)],
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
                "orealloc_probe",
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
            "orealloc_probe\t/usr/local/bin/orealloc_probe\tobsd_applet_orealloc_probe_main\tapplets/orealloc_probe.o\n",
            encoding="utf-8",
        )

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
                "MALLOC_OPTIONS=JJ /usr/local/bin/orealloc_probe",
            ],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if proc.returncode != 0:
            raise AssertionError(f"orealloc guard test failed (rc={proc.returncode}):\n{proc.stdout}")
        expected_line = f"CHUNK_OREALLOC_OK={224 * 131072}"
        if expected_line not in proc.stdout.splitlines():
            raise AssertionError(f"missing '{expected_line}' in output:\n{proc.stdout}")

    print(f"[SDK-TEST] [{openbsd_version}] 16 MiB chunk guard gap multi-page orealloc+free (28 MiB, MALLOC_OPTIONS=JJ): PASS")


def test_only_versions_and_skip_distfiles(obsd_root: pathlib.Path) -> None:
    with tempfile.TemporaryDirectory(prefix="obsd-test-recipes-") as td:
        tp = pathlib.Path(td)
        ports_root = tp / "ports"

        # 1. Test `only_versions` filtering across 7.8, 7.9, 8.0 (full discovery + targeted PORT=...)
        (ports_root / "devel/common").mkdir(parents=True)
        (ports_root / "devel/common/port.toml").write_text(
            'port = "devel/common"\nbuild_style = "make"\n',
            encoding="utf-8",
        )
        (ports_root / "graphics/sd").mkdir(parents=True)
        (ports_root / "graphics/sd/port.toml").write_text(
            'port = "graphics/sd"\nonly_versions = ["7.9", "8.0"]\ndepends = ["devel/common"]\nbuild_style = "cmake"\n',
            encoding="utf-8",
        )
        (ports_root / "devel/agent80").mkdir(parents=True)
        (ports_root / "devel/agent80/port.toml").write_text(
            'port = "devel/agent80"\nonly_versions = ["8.0"]\ndepends = ["devel/common"]\nbuild_style = "make"\n',
            encoding="utf-8",
        )

        r78 = [r["port"] for r in bp.discover_recipes("7.8", ports_root=ports_root)]
        r79 = [r["port"] for r in bp.discover_recipes("7.9", ports_root=ports_root)]
        r80 = [r["port"] for r in bp.discover_recipes("8.0", ports_root=ports_root)]
        assert r78 == ["devel/common"], f"unexpected 7.8 recipes: {r78}"
        assert r79 == ["devel/common", "graphics/sd"], f"unexpected 7.9 recipes: {r79}"
        assert r80 == ["devel/common", "devel/agent80", "graphics/sd"] or set(r80) == {"devel/common", "devel/agent80", "graphics/sd"}
        assert r80[0] == "devel/common"

        # Targeted discovery cleanly skips recipes excluded on an older release without erroring
        assert bp.discover_recipes("7.8", ["graphics/sd"], ports_root=ports_root) == []
        assert bp.discover_recipes("7.9", ["devel/agent80"], ports_root=ports_root) == []
        assert [r["port"] for r in bp.discover_recipes("7.9", ["graphics/sd"], ports_root=ports_root)] == ["devel/common", "graphics/sd"]

        # 2. Test `skip_distfiles` in `fetch_port_distfiles()` and `build_single_port()`
        fake_repo = tp / "repo"
        vport_dir = fake_repo / "vendor/openbsd/versions/8.0/ports/audio/mock-whisper"
        vport_dir.mkdir(parents=True)
        (fake_repo / "vendor/openbsd/versions/8.0/ports/infrastructure/db").mkdir(parents=True)
        (fake_repo / "vendor/openbsd/versions/8.0/ports/infrastructure/db/network.conf").write_text("", encoding="utf-8")

        tar_buf = io.BytesIO()
        with tarfile.open(fileobj=tar_buf, mode="w:gz") as tf:
            payload = b"#!/bin/sh\necho ok\n"
            ti = tarfile.TarInfo("mock-whisper-1.0/hello.sh")
            ti.size = len(payload)
            ti.mode = 0o755
            tf.addfile(ti, io.BytesIO(payload))
        tar_bytes = tar_buf.getvalue()
        tar_sha = bp.hashlib.sha256(tar_bytes).hexdigest()

        cache_dist = fake_repo / ".cache/distfiles"
        cache_dist.mkdir(parents=True)
        (cache_dist / "mock-whisper-1.0.tar.gz").write_bytes(tar_bytes)
        # Intentionally DO NOT create `ggml-base.en.bin` in `.cache/distfiles` (and give it an unreachable URL):
        # `fetch_port_distfiles` + `build_single_port` MUST skip it cleanly without downloading or extracting it.
        (vport_dir / "Makefile").write_text(
            "DISTNAME =\tmock-whisper-1.0\n"
            "DISTFILES.ggml =\tggml-base.en.bin\n"
            "SITES =\thttp://127.0.0.1:9/unreachable/\n"
            "SITES.ggml =\thttp://127.0.0.1:9/unreachable/\n",
            encoding="utf-8",
        )
        fake_bin_sha = "0" * 64
        (vport_dir / "distinfo").write_text(
            f"SHA256 (ggml-base.en.bin) = {fake_bin_sha}\n"
            f"SHA256 (mock-whisper-1.0.tar.gz) = {tar_sha}\n"
            f"SIZE (ggml-base.en.bin) = 147964211\n"
            f"SIZE (mock-whisper-1.0.tar.gz) = {len(tar_bytes)}\n",
            encoding="utf-8",
        )

        mock_port_dir = fake_repo / "ports/audio/mock-whisper"
        mock_port_dir.mkdir(parents=True)
        (mock_port_dir / "port.toml").write_text(
            'port = "audio/mock-whisper"\n'
            'build_style = "script"\n'
            'skip_distfiles = ["ggml-base.en.bin"]\n'
            'build_cmd = ["cp hello.sh \\"$STAGE_DIR/usr/local/bin/mock-whisper\\""]\n',
            encoding="utf-8",
        )
        rec = bp.load_recipe(mock_port_dir, "8.0", ports_root=fake_repo / "ports")
        fetched = bp.fetch_port_distfiles(rec, "8.0", repo_root=fake_repo)
        assert [ent["filename"] for _, ent in fetched] == ["mock-whisper-1.0.tar.gz"]
        assert not (cache_dist / "ggml-base.en.bin").exists()

        lane_dir = tp / "lane"
        built_rec = bp.build_single_port(
            recipe=rec,
            openbsd_version="8.0",
            backend="emulate",
            pal="emscripten",
            obsd_root=obsd_root,
            lane_dir=lane_dir,
            jobs=1,
            repo_root=fake_repo,
        )
        assert "usr/local/bin/mock-whisper" in built_rec["installed_files"]
        assert built_rec["signature"]

        # 3. Verify bmake `:S` / `:C` modifiers & `CMAKE_SYSTEM_PROCESSOR` override in `openbsd-wasm64.cmake`
        env_sd = {"GH_TAGNAME": "master-899-28b454b"}
        assert bp.expand_openbsd_expr("stable-diffusion.cpp-0.0.${GH_TAGNAME:S/master-//:C/-.+//g}", env_sd) == "stable-diffusion.cpp-0.0.899"

        cmake_probe = tp / "cmake_probe"
        cmake_probe.mkdir()
        (cmake_probe / "CMakeLists.txt").write_text(
            "cmake_minimum_required(VERSION 3.16)\n"
            "project(proc_probe LANGUAGES NONE)\n"
            'message(STATUS "PROC=${CMAKE_SYSTEM_PROCESSOR}")\n',
            encoding="utf-8",
        )
        tc_file = REPO_ROOT / "sdk/cmake/openbsd-wasm64.cmake"
        p_def = subprocess.run(
            ["cmake", "-S", str(cmake_probe), "-B", str(cmake_probe / "b_def"), f"-DCMAKE_TOOLCHAIN_FILE={tc_file}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=True,
        )
        assert "PROC=aarch64" in p_def.stdout, p_def.stdout
        p_ovr = subprocess.run(
            [
                "cmake",
                "-S",
                str(cmake_probe),
                "-B",
                str(cmake_probe / "b_ovr"),
                f"-DCMAKE_TOOLCHAIN_FILE={tc_file}",
                "-DCMAKE_SYSTEM_PROCESSOR=wasm64",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=True,
        )
        assert "PROC=wasm64" in p_ovr.stdout, p_ovr.stdout

    print("[SDK-TEST] only_versions + skip_distfiles + CMAKE_SYSTEM_PROCESSOR override: PASS")


def test_matrix_and_package_desc_emission() -> None:
    import json

    obsd_cargo = REPO_ROOT / "sdk/bin/obsd-cargo"
    expected_5_cells = {
        ("emulate", "emscripten"),
        ("emulate", "wasi"),
        ("emulate", "darwin"),
        ("translate", "darwin"),
        ("translate", "linux"),
    }
    seen_cells = set()
    for raw in (REPO_ROOT / "config/matrix/index.tsv").read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if not s or s.startswith("#") or s.startswith("backend\t"):
            continue
        cols = raw.split("\t")
        seen_cells.add((cols[0].strip(), cols[1].strip()))
    assert seen_cells == expected_5_cells, f"expected 5-cell matrix {expected_5_cells}, got {seen_cells}"

    for sdk_arg, exp_triple in (
        ("iphonesimulator", "aarch64-apple-ios-sim"),
        ("iphoneos", "aarch64-apple-ios"),
    ):
        out = subprocess.check_output(
            [
                str(obsd_cargo),
                "target-info",
                "--openbsd-version",
                "8.0",
                "--backend",
                "emulate",
                "--pal",
                "darwin",
                "--sdk",
                sdk_arg,
            ],
            text=True,
        )
        assert json.loads(out)["target_name"] == exp_triple
    out_tr = subprocess.check_output(
        [
            str(obsd_cargo),
            "target-info",
            "--openbsd-version",
            "8.0",
            "--backend",
            "translate",
            "--pal",
            "darwin",
        ],
        text=True,
    )
    assert json.loads(out_tr)["target_name"] == "aarch64-apple-darwin"

    # Verify Darwin recipes discover cleanly (53 C/C++ ports) while Emscripten discovers full 98
    darwin_recs = bp.discover_recipes("8.0", backend="emulate", pal="darwin", section="all")
    wasm_recs = bp.discover_recipes("8.0", backend="emulate", pal="emscripten", section="all")
    assert len(darwin_recs) == 53, f"expected 53 Darwin ports, got {len(darwin_recs)}"
    assert len(wasm_recs) == 98, f"expected 98 WASM ports, got {len(wasm_recs)}"

    # Verify emit_port_packages writes both +CONTENTS and +DESC into <pkgname>.tgz
    with tempfile.TemporaryDirectory(prefix="obsd-test-pkgdesc-") as td:
        tp = pathlib.Path(td)
        lane_dir = tp / "lane"
        stage_dir = lane_dir / "stage"
        (stage_dir / "usr/local/bin").mkdir(parents=True)
        (stage_dir / "usr/local/bin/demo").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        cnt = pw.emit_port_packages(
            lane_dir=lane_dir,
            stage_dir=stage_dir,
            records=[
                {
                    "port": "devel/demo",
                    "pkgname": "demo-1.0",
                    "openbsd_version": "8.0",
                    "comment": "demo CLI tool",
                    "descr": "Full multi-line description of demo.",
                    "installed_files": ["usr/local/bin/demo"],
                }
            ],
        )
        assert cnt == 1
        with tarfile.open(lane_dir / "packages/demo-1.0.tgz", "r:gz") as tf:
            names = tf.getnames()
            assert "+CONTENTS" in names and "+DESC" in names, names
            desc_body = tf.extractfile("+DESC").read().decode("utf-8")  # type: ignore[union-attr]
            assert desc_body == "demo CLI tool\nFull multi-line description of demo.\n", desc_body

    print("[SDK-TEST] canonical 5-cell matrix + Darwin COMPAT_SDK target-info + package +DESC emission: PASS")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--openbsd-version", default=os.environ.get("OPENBSD_VERSION", "all"))
    ap.add_argument("--libobsdcompat-root", default="")
    args = ap.parse_args()

    obsd_root = resolve_obsd_root(args.libobsdcompat_root)
    target = args.openbsd_version.strip()
    versions: List[str] = obsd_versions.resolve_versions(target)

    test_lzip_extraction()
    test_only_versions_and_skip_distfiles(obsd_root)
    test_matrix_and_package_desc_emission()
    for ver in versions:
        test_symlink_alias_discovery(ver, obsd_root)
        test_cxx17_build_localize_and_run(ver, obsd_root)
        test_chunk_boundary_orealloc_guard(ver, obsd_root)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
