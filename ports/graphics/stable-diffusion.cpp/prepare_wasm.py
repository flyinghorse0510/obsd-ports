#!/usr/bin/env python3
"""
prepare_wasm.py -- Multi-call WASM64 packaging & isolated install helper for
graphics/stable-diffusion.cpp across OpenBSD 7.9 (0.0.537545fac4) and 8.0 (0.0.899).
"""
from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess
import sys


SD_MULTICALL_CPP = r'''
#include <cstdio>
#include <cstring>
#include <string>

extern "C" {
int sd_cli_entry(int argc, const char ** argv);
int sd_server_entry(int argc, const char ** argv);
}

static std::string base_name(const char * p) {
    if (!p) return "sd-cli";
    std::string s(p);
    auto pos = s.find_last_of('/');
    return pos == std::string::npos ? s : s.substr(pos + 1);
}

static int print_help(const char * prog) {
    std::printf(
        "Usage: %s <command> [options]\n\n"
        "Available commands:\n"
        "  cli     Run image/video diffusion inference (sd-cli)\n"
        "  server  Run OpenAI-compatible HTTP diffusion server (sd-server)\n",
        prog ? prog : "sd"
    );
    return 0;
}

int main(int argc, char ** argv) {
    const char ** cargv = const_cast<const char **>(argv);
    const std::string b = base_name(argc > 0 ? argv[0] : "sd");
    if (b == "sd-cli")    return sd_cli_entry(argc, cargv);
    if (b == "sd-server") return sd_server_entry(argc, cargv);

    if (argc < 2) {
        return print_help(argv[0]);
    }
    const std::string sub(argv[1]);
    if (sub == "help" || sub == "--help" || sub == "-h") {
        return print_help(argv[0]);
    }
    if (sub == "cli")                       return sd_cli_entry(argc - 1, cargv + 1);
    if (sub == "server" || sub == "serve")  return sd_server_entry(argc - 1, cargv + 1);

    // Convenience: if invoked as `sd -m ...` or `sd --version`, forward directly to sd-cli
    if (!sub.empty() && sub[0] == '-') {
        return sd_cli_entry(argc, cargv);
    }
    std::fprintf(stderr, "error: unknown command '%s'\n", sub.c_str());
    return 1;
}
'''


def rewrite_sd_main(cpp_path: pathlib.Path, entry_name: str, extra_renames: dict[str, str] | None = None) -> None:
    src = cpp_path.read_text(encoding="utf-8")
    marker = f'extern "C" int {entry_name}('
    if marker in src:
        return
    if extra_renames:
        for old_nm, new_nm in extra_renames.items():
            src = re.sub(rf"\b{re.escape(old_nm)}\b", new_nm, src)
    new_src, count = re.subn(
        r"\bint\s+main\s*\(\s*int\s+(\w+)\s*,\s*const\s+char\s*\*\s*(\w+)\s*\[\s*\]\s*\)",
        rf'extern "C" int {entry_name}(int \1, const char ** \2)',
        src,
        count=1,
    )
    if count != 1:
        new_src, count = re.subn(
            r"\bint\s+main\s*\(\s*int\s+(\w+)\s*,\s*const\s+char\s*\*\*\s*(\w+)\s*\)",
            rf'extern "C" int {entry_name}(int \1, const char ** \2)',
            src,
            count=1,
        )
    if count != 1:
        raise SystemExit(f"prepare_wasm.py: failed to rewrite main in {cpp_path}")
    cpp_path.write_text(new_src, encoding="utf-8")


def prepare_source() -> None:
    ver = os.environ["OPENBSD_VERSION"].strip()
    wrksrc = pathlib.Path(os.environ["WRKSRC"])
    vendor_port_dir = pathlib.Path(os.environ["VENDOR_PORT_DIR"])

    # 1. Populate bundled ggml submodule from extracted sibling ../ggml-<hash> (OpenBSD post-extract)
    ggml_dst = wrksrc / "ggml"
    if not (ggml_dst / "CMakeLists.txt").is_file():
        siblings = sorted(p for p in wrksrc.parent.iterdir() if p.is_dir() and p.name.startswith("ggml-"))
        if not siblings:
            raise SystemExit(f"prepare_wasm.py: extracted ggml-* directory not found under {wrksrc.parent}")
        if ggml_dst.exists():
            shutil.rmtree(ggml_dst)
        shutil.move(str(siblings[0]), str(ggml_dst))

    for pname in ("patch-ggml_CMakeLists_txt", "patch-ggml_src_ggml-backend-reg_cpp"):
        pf = vendor_port_dir / "patches" / pname
        if pf.is_file():
            subprocess.run(
                ["patch", "-p0", "-f", "-N", "-s", "--no-backup-if-mismatch", "-d", str(wrksrc)],
                stdin=pf.open("rb"),
                check=True,
            )

    ops_h = wrksrc / "ggml/src/ggml-cpu/ops.h"
    if ops_h.is_file():
        osrc = ops_h.read_text(encoding="utf-8")
        if "hardware_destructive_interference_size" in osrc:
            ops_h.write_text(
                osrc.replace("#if defined(__cpp_lib_hardware_interference_size)", "#if 0"),
                encoding="utf-8",
            )

    # Ensure 7.9 installs static ARCHIVE libstable-diffusion.a too
    top_cmake = wrksrc / "CMakeLists.txt"
    tc_src = top_cmake.read_text(encoding="utf-8")
    if "install(TARGETS ${SD_LIB} LIBRARY PUBLIC_HEADER)" in tc_src:
        tc_src = tc_src.replace(
            "install(TARGETS ${SD_LIB} LIBRARY PUBLIC_HEADER)",
            "install(TARGETS ${SD_LIB} ARCHIVE LIBRARY PUBLIC_HEADER)",
            1,
        )
        top_cmake.write_text(tc_src, encoding="utf-8")

    # 2. Combine sd-cli and sd-server into one multi-call `sd` closure
    common_hpp = wrksrc / "examples/common/common.hpp"
    if common_hpp.is_file():
        ch_src = common_hpp.read_text(encoding="utf-8")
        for needle, repl in (
            ("\nconst char* modes_str[] =", "\nstatic const char* modes_str[] ="),
            ("\nuint8_t* load_image_common(", "\nstatic inline uint8_t* load_image_common("),
            ("\nuint8_t* load_image_from_file(", "\nstatic inline uint8_t* load_image_from_file("),
            ("\nbool load_sd_image_from_file(", "\nstatic inline bool load_sd_image_from_file("),
            ("\nuint8_t* load_image_from_memory(", "\nstatic inline uint8_t* load_image_from_memory("),
        ):
            ch_src = ch_src.replace(needle, repl)
        common_hpp.write_text(ch_src, encoding="utf-8")

    rewrite_sd_main(
        wrksrc / "examples/cli/main.cpp",
        "sd_cli_entry",
        {"sd_log_cb": "sd_cli_log_cb", "print_usage": "sd_cli_print_usage", "parse_args": "sd_cli_parse_args"},
    )
    rewrite_sd_main(
        wrksrc / "examples/server/main.cpp",
        "sd_server_entry",
        {"sd_log_cb": "sd_srv_log_cb", "print_usage": "sd_srv_print_usage", "parse_args": "sd_srv_parse_args"},
    )

    mc_cpp = wrksrc / "examples/sd_multicall.cpp"
    mc_cpp.write_text(SD_MULTICALL_CPP, encoding="utf-8")

    if ver == "7.9":
        (wrksrc / "examples/CMakeLists.txt").write_text(
            "include_directories(${CMAKE_CURRENT_SOURCE_DIR})\n"
            "add_executable(sd\n"
            "    sd_multicall.cpp\n"
            "    cli/main.cpp\n"
            "    server/main.cpp\n"
            ")\n"
            "target_link_libraries(sd PRIVATE stable-diffusion ${CMAKE_THREAD_LIBS_INIT})\n"
            "target_compile_features(sd PUBLIC c_std_11 cxx_std_17)\n"
            "install(TARGETS sd RUNTIME)\n",
            encoding="utf-8",
        )
    else:
        (wrksrc / "examples/CMakeLists.txt").write_text(
            "include_directories(${CMAKE_CURRENT_SOURCE_DIR})\n"
            "add_executable(sd\n"
            "    sd_multicall.cpp\n"
            "    common/common.cpp\n"
            "    common/log.cpp\n"
            "    common/media_io.cpp\n"
            "    cli/image_metadata.cpp\n"
            "    cli/main.cpp\n"
            "    server/main.cpp\n"
            "    server/runtime.cpp\n"
            "    server/async_jobs.cpp\n"
            "    server/routes_index.cpp\n"
            "    server/routes_openai.cpp\n"
            "    server/routes_sdapi.cpp\n"
            "    server/routes_sdcpp.cpp\n"
            ")\n"
            'target_include_directories(sd PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}" "${PROJECT_SOURCE_DIR}/src" "${CMAKE_CURRENT_SOURCE_DIR}/cli" "${CMAKE_CURRENT_SOURCE_DIR}/server")\n'
            "target_link_libraries(sd PRIVATE stable-diffusion zip ${CMAKE_THREAD_LIBS_INIT})\n"
            "target_compile_features(sd PUBLIC c_std_11 cxx_std_17)\n"
            "install(TARGETS sd RUNTIME)\n",
            encoding="utf-8",
        )


def isolated_install() -> None:
    wrksrc = pathlib.Path(os.environ["WRKSRC"])
    wrkbuild = pathlib.Path(os.environ["WRKBUILD"])
    stage_dir = pathlib.Path(os.environ["STAGE_DIR"])

    tmp_dest = wrkbuild / "_sd_dest"
    if tmp_dest.exists():
        shutil.rmtree(tmp_dest)
    inst_env = dict(os.environ)
    inst_env["DESTDIR"] = str(tmp_dest)
    subprocess.run(["cmake", "--install", str(wrkbuild)], env=inst_env, check=True)

    usr_local = tmp_dest / "usr/local"
    # Strip bundled ggml artifacts so devel/libggml in $STAGE_DIR is never overwritten!
    for pat in ("include/ggml*", "include/gguf*", "lib/libggml*", "lib/pkgconfig/ggml*", "share/pkgconfig/ggml*"):
        for p in usr_local.glob(pat):
            if p.is_dir() and not p.is_symlink():
                shutil.rmtree(p)
            else:
                p.unlink(missing_ok=True)
    shutil.rmtree(usr_local / "lib/cmake", ignore_errors=True)

    # Create sd-cli and sd-server multi-call symlinks -> sd
    bin_dir = usr_local / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    for alias in ("sd-cli", "sd-server"):
        ap = bin_dir / alias
        if ap.exists() or ap.is_symlink():
            ap.unlink()
        os.symlink("sd", ap)

    # Stage documentation matching OpenBSD port post-install
    doc_dst = usr_local / "share/doc/stable-diffusion.cpp"
    doc_dst.mkdir(parents=True, exist_ok=True)
    docs_src = wrksrc / "docs"
    if docs_src.is_dir():
        for doc_f in sorted(docs_src.iterdir()):
            if doc_f.is_file():
                shutil.copy2(doc_f, doc_dst / doc_f.name)

    # Copy clean tree into $STAGE_DIR/usr/local
    subprocess.run(["cp", "-a", f"{usr_local}/.", f"{stage_dir / 'usr/local'}/"], check=True)


def main() -> None:
    if "--install" in sys.argv:
        isolated_install()
    else:
        prepare_source()


if __name__ == "__main__":
    main()
