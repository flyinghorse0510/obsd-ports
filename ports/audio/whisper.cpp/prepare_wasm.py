#!/usr/bin/env python3
"""
prepare_wasm.py -- Multi-call WASM64 packaging & download script helper for audio/whisper.cpp
across OpenBSD 7.8 (1.7.6), 7.9 (1.8.4), and 8.0 (1.9.4).
"""
from __future__ import annotations

import os
import pathlib
import re
import shutil
import stat
import sys


WHISPER_MULTICALL_CPP = r'''
#include "whisper.h"
#include <cstdio>
#include <cstring>
#include <string>

extern "C" {
int whisper_cli_entry(int argc, char ** argv);
int whisper_server_entry(int argc, char ** argv);
int whisper_bench_entry(int argc, char ** argv);
int whisper_quantize_entry(int argc, char ** argv);
}

static std::string base_name(const char * p) {
    if (!p) return "whisper";
    std::string s(p);
    auto pos = s.find_last_of('/');
    return pos == std::string::npos ? s : s.substr(pos + 1);
}

static int print_help(const char * prog) {
    std::printf(
        "Usage: %s <command> [options]\n\n"
        "Available commands:\n"
        "  cli       Transcribe audio files with Whisper (whisper-cli)\n"
        "  server    OpenAI /inference HTTP speech server (whisper-server)\n"
        "  bench     Benchmark Whisper encoder/decoder speed (whisper-bench)\n"
        "  quantize  Quantize GGML Whisper models (whisper-quantize)\n",
        prog ? prog : "whisper"
    );
    return 0;
}

int main(int argc, char ** argv) {
    const std::string b = base_name(argc > 0 ? argv[0] : "whisper");
    if (b == "whisper-cli")      return whisper_cli_entry(argc, argv);
    if (b == "whisper-server")   return whisper_server_entry(argc, argv);
    if (b == "whisper-bench")    return whisper_bench_entry(argc, argv);
    if (b == "whisper-quantize") return whisper_quantize_entry(argc, argv);

    if (argc < 2) {
        return print_help(argv[0]);
    }
    const std::string sub(argv[1]);
    if (sub == "help" || sub == "--help" || sub == "-h") {
        return print_help(argv[0]);
    }
    if (sub == "version" || sub == "--version" || sub == "-v") {
        std::printf("whisper.cpp (%s)\n", whisper_print_system_info());
        return 0;
    }
    if (sub == "cli")                       return whisper_cli_entry(argc - 1, argv + 1);
    if (sub == "server" || sub == "serve")  return whisper_server_entry(argc - 1, argv + 1);
    if (sub == "bench")                     return whisper_bench_entry(argc - 1, argv + 1);
    if (sub == "quantize")                  return whisper_quantize_entry(argc - 1, argv + 1);

    std::fprintf(stderr, "error: unknown command '%s'\n", sub.c_str());
    return 1;
}
'''


def rewrite_main_entry(cpp_path: pathlib.Path, entry_name: str, extra_renames: dict[str, str] | None = None) -> None:
    src = cpp_path.read_text(encoding="utf-8")
    marker = f'extern "C" int {entry_name}('
    if marker in src:
        return
    if extra_renames:
        for old_nm, new_nm in extra_renames.items():
            src = re.sub(rf"\b{re.escape(old_nm)}\b", new_nm, src)
    new_src, count = re.subn(
        r"\bint\s+main\s*\(\s*int\s+(\w+)\s*,\s*(?:const\s+)?char\s*\*\s*(?:const\s*)?\*\s*(\w+)\s*\)",
        rf'extern "C" int {entry_name}(int \1, char ** \2)',
        src,
        count=1,
    )
    if count != 1:
        new_src, count = re.subn(
            r"\bint\s+main\s*\(\s*int\s+(\w+)\s*,\s*(?:const\s+)?char\s*\*\s*(\w+)\s*\[\s*\]\s*\)",
            rf'extern "C" int {entry_name}(int \1, char ** \2)',
            src,
            count=1,
        )
    if count != 1:
        raise SystemExit(f"prepare_wasm.py: failed to rewrite main in {cpp_path}")
    cpp_path.write_text(new_src, encoding="utf-8")


def prepare_source(wrksrc: pathlib.Path) -> None:
    # Rename any non-static helper collisions across cli/server/bench/quantize
    rewrite_main_entry(
        wrksrc / "examples/cli/cli.cpp",
        "whisper_cli_entry",
        {"whisper_params": "whisper_cli_params", "whisper_print_usage": "whisper_cli_print_usage", "whisper_params_parse": "whisper_cli_params_parse"},
    )
    rewrite_main_entry(
        wrksrc / "examples/server/server.cpp",
        "whisper_server_entry",
        {"whisper_params": "whisper_srv_params", "whisper_print_usage": "whisper_srv_print_usage", "whisper_params_parse": "whisper_srv_params_parse"},
    )
    rewrite_main_entry(
        wrksrc / "examples/bench/bench.cpp",
        "whisper_bench_entry",
        {"whisper_params": "whisper_bench_params", "whisper_print_usage": "whisper_bench_print_usage", "whisper_params_parse": "whisper_bench_params_parse"},
    )
    rewrite_main_entry(
        wrksrc / "examples/quantize/quantize.cpp",
        "whisper_quantize_entry",
    )

    (wrksrc / "examples/cli/CMakeLists.txt").write_text(
        "add_library(whisper_cli_obj OBJECT cli.cpp)\n"
        "include(DefaultTargetOptions)\n"
        "target_link_libraries(whisper_cli_obj PRIVATE common whisper ${CMAKE_THREAD_LIBS_INIT})\n",
        encoding="utf-8",
    )
    (wrksrc / "examples/server/CMakeLists.txt").write_text(
        "set(CMAKE_CXX_STANDARD 17)\n"
        "set(CMAKE_CXX_STANDARD_REQUIRED ON)\n"
        "add_library(whisper_server_obj OBJECT server.cpp httplib.h)\n"
        "include(DefaultTargetOptions)\n"
        "target_link_libraries(whisper_server_obj PRIVATE common json_cpp whisper ${CMAKE_THREAD_LIBS_INIT})\n",
        encoding="utf-8",
    )
    (wrksrc / "examples/bench/CMakeLists.txt").write_text(
        "add_library(whisper_bench_obj OBJECT bench.cpp)\n"
        "include(DefaultTargetOptions)\n"
        "target_link_libraries(whisper_bench_obj PRIVATE whisper ${CMAKE_THREAD_LIBS_INIT})\n",
        encoding="utf-8",
    )
    (wrksrc / "examples/quantize/CMakeLists.txt").write_text(
        "add_library(whisper_quantize_obj OBJECT quantize.cpp)\n"
        "include(DefaultTargetOptions)\n"
        "target_link_libraries(whisper_quantize_obj PRIVATE common whisper ${CMAKE_THREAD_LIBS_INIT})\n",
        encoding="utf-8",
    )

    mc_dir = wrksrc / "examples/multicall"
    mc_dir.mkdir(parents=True, exist_ok=True)
    (mc_dir / "whisper_multicall.cpp").write_text(WHISPER_MULTICALL_CPP, encoding="utf-8")
    (mc_dir / "CMakeLists.txt").write_text(
        "add_executable(whisper-app\n"
        "    whisper_multicall.cpp\n"
        "    $<TARGET_OBJECTS:whisper_cli_obj>\n"
        "    $<TARGET_OBJECTS:whisper_server_obj>\n"
        "    $<TARGET_OBJECTS:whisper_bench_obj>\n"
        "    $<TARGET_OBJECTS:whisper_quantize_obj>\n"
        ")\n"
        "set_target_properties(whisper-app PROPERTIES OUTPUT_NAME whisper)\n"
        "include(DefaultTargetOptions)\n"
        "target_compile_features(whisper-app PRIVATE cxx_std_17)\n"
        "target_link_libraries(whisper-app PRIVATE common json_cpp whisper ${CMAKE_THREAD_LIBS_INIT})\n"
        "install(TARGETS whisper-app RUNTIME)\n",
        encoding="utf-8",
    )

    ex_cmake = wrksrc / "examples/CMakeLists.txt"
    ex_src = ex_cmake.read_text(encoding="utf-8")
    # Replace the non-EMSCRIPTEN add_subdirectory block with our clean 5 targets
    idx = ex_src.find("# examples")
    if idx == -1:
        raise SystemExit("prepare_wasm.py: '# examples' section not found in examples/CMakeLists.txt")
    ex_cmake.write_text(
        ex_src[:idx]
        + "# examples\n"
        + "include_directories(${CMAKE_CURRENT_SOURCE_DIR})\n"
        + "add_subdirectory(cli)\n"
        + "add_subdirectory(bench)\n"
        + "add_subdirectory(server)\n"
        + "add_subdirectory(quantize)\n"
        + "add_subdirectory(multicall)\n",
        encoding="utf-8",
    )

    # Ensure models/download-ggml-model.sh uses curl + /etc/ssl/cert.pem cleanly on all 3 releases
    dl_sh = wrksrc / "models/download-ggml-model.sh"
    dsrc = dl_sh.read_text(encoding="utf-8")
    # Normalize OpenBSD 7.8's bare `ftp -o ...` and 7.9/8.0's curl call to pass --cacert /etc/ssl/cert.pem when present
    curl_cmd = (
        'if [ -x "$(command -v curl)" ]; then\n'
        '    if [ -f /etc/ssl/cert.pem ]; then\n'
        '        curl -fL --cacert /etc/ssl/cert.pem --output ggml-"$model".bin "$src/$pfx-$model.bin"\n'
        '    else\n'
        '        curl -fL --output ggml-"$model".bin "$src/$pfx-$model.bin"\n'
        '    fi\n'
        'else\n'
        '    ftp -mV -o ggml-"$model".bin "$src/$pfx-$model.bin"\n'
        'fi'
    )
    if 'ftp -o ggml-"$model".bin $src/$pfx-"$model".bin' in dsrc:
        dsrc = dsrc.replace('ftp -o ggml-"$model".bin $src/$pfx-"$model".bin', curl_cmd, 1)
    elif "curl -L --fail \\" in dsrc:
        dsrc = dsrc.replace(
            "curl -L --fail \\",
            'curl -L --fail $([ -f /etc/ssl/cert.pem ] && printf "%s" "--cacert /etc/ssl/cert.pem") \\',
            1,
        )
    else:
        dsrc = dsrc.replace(
            'curl -L --output ggml-"$model".bin $src/$pfx-"$model".bin',
            'if [ -f /etc/ssl/cert.pem ]; then curl -fL --cacert /etc/ssl/cert.pem --output ggml-"$model".bin "$src/$pfx-$model.bin"; else curl -fL --output ggml-"$model".bin "$src/$pfx-$model.bin"; fi',
        )
    # Use portable POSIX ANSI escapes if tput fails on dumb/non-tty stdout
    dsrc = dsrc.replace("BOLD=$(tput bold)", 'BOLD=$(tput bold 2>/dev/null || true)')
    dsrc = dsrc.replace("RESET=$(tput sgr0)", 'RESET=$(tput sgr0 2>/dev/null || true)')
    dl_sh.write_text(dsrc, encoding="utf-8")


def post_install(wrksrc: pathlib.Path, stage_dir: pathlib.Path, ver: str) -> None:
    bin_dir = stage_dir / "usr/local/bin"
    sbin_dir = stage_dir / "usr/local/sbin"
    share_dir = stage_dir / "usr/local/share/whisper.cpp"
    bin_dir.mkdir(parents=True, exist_ok=True)
    sbin_dir.mkdir(parents=True, exist_ok=True)
    share_dir.mkdir(parents=True, exist_ok=True)

    for alias in ("whisper-cli", "whisper-server", "whisper-bench", "whisper-quantize"):
        p = bin_dir / alias
        if p.exists() or p.is_symlink():
            p.unlink()
        os.symlink("whisper", p)

    if ver in ("7.9", "8.0"):
        sp = sbin_dir / "whisper-server"
        if sp.exists() or sp.is_symlink():
            sp.unlink()
        os.symlink("../bin/whisper", sp)

    dl_dst = bin_dir / "whisper.cpp-download-ggml-model"
    shutil.copy2(wrksrc / "models/download-ggml-model.sh", dl_dst)
    dl_dst.chmod(0o755)


def main() -> None:
    ver = os.environ["OPENBSD_VERSION"].strip()
    wrksrc = pathlib.Path(os.environ["WRKSRC"])
    if "--post-install" in sys.argv:
        post_install(wrksrc, pathlib.Path(os.environ["STAGE_DIR"]), ver)
    else:
        prepare_source(wrksrc)


if __name__ == "__main__":
    main()
