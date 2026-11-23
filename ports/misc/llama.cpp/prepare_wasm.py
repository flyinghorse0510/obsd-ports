#!/usr/bin/env python3
"""
prepare_wasm.py -- WASM64 preparation & multi-call packaging helper for misc/llama.cpp
across OpenBSD 7.8 (b6641), 7.9 (b8631), and 8.0 (0.5.0).

Handles:
  1. Automatic VFS mmap fallback (`llama_mmap::SUPPORTED = false` on WASM + try/catch
     fallback in `llama_model_loader::init_mappings`) so `llama-cli -m model.gguf` and
     `llama-server -m model.gguf` work out-of-the-box without `--no-mmap`.
  2. Base OpenBSD LibreSSL discovery (`7.9` & `8.0`) for HTTPS `-hf` model downloads.
  3. OpenBSD `8.0` Svelte Agentic + MCP WebUI asset extraction (`llama.cpp-0.5.0-ui-dist.tar.gz`).
  4. Single-closure C++ `argv[0]` + subcommand multi-call packaging across all 3 releases.
"""
from __future__ import annotations

import os
import pathlib
import re
import sys
import tarfile


def rewrite_main_entry(cpp_path: pathlib.Path, entry_name: str) -> None:
    src = cpp_path.read_text(encoding="utf-8")
    marker = f'extern "C" int {entry_name}('
    if marker in src:
        return
    new_src, count = re.subn(
        r"\bint\s+main\s*\(\s*int\s+(\w+)\s*,\s*char\s*\*\*\s*(\w+)\s*\)",
        rf'extern "C" int {entry_name}(int \1, char ** \2)',
        src,
        count=1,
    )
    if count != 1:
        raise SystemExit(f"prepare_wasm.py: failed to rewrite int main(...) in {cpp_path}")
    cpp_path.write_text(new_src, encoding="utf-8")


def patch_mmap_fallback(wrksrc: pathlib.Path) -> None:
    mmap_cpp = wrksrc / "src/llama-mmap.cpp"
    msrc = mmap_cpp.read_text(encoding="utf-8")
    target = "#if defined(_POSIX_MEMLOCK_RANGE) || defined(_WIN32)\nconst bool llama_mmap::SUPPORTED  = true;"
    repl = (
        "#if defined(__wasm__) || defined(__wasm64__)\n"
        "const bool llama_mmap::SUPPORTED  = false;\n"
        "#elif defined(_POSIX_MEMLOCK_RANGE) || defined(_WIN32)\n"
        "const bool llama_mmap::SUPPORTED  = true;"
    )
    if repl not in msrc:
        if target not in msrc:
            raise SystemExit(f"prepare_wasm.py: llama_mmap::SUPPORTED anchor not found in {mmap_cpp}")
        msrc = msrc.replace(target, repl, 1)
        mmap_cpp.write_text(msrc, encoding="utf-8")

    loader_cpp = wrksrc / "src/llama-model-loader.cpp"
    lsrc = loader_cpp.read_text(encoding="utf-8")
    warn_needle = 'LLAMA_LOG_WARN("%s: mmap is not supported on this platform\\n", __func__);'
    warn_repl = 'LLAMA_LOG_DEBUG("%s: mmap disabled on WASM VFS; using standard file read\\n", __func__);'
    if warn_needle in lsrc:
        lsrc = lsrc.replace(warn_needle, warn_repl, 1)

    # Also guard init_mappings with try/catch fallback in case use_mmap was forced
    init_needle = "void llama_model_loader::init_mappings("
    if init_needle in lsrc and "falling back to read I/O" not in lsrc:
        m = re.search(
            r"(void\s+llama_model_loader::init_mappings\s*\([^{]+\{\s*if\s*\(\s*use_mmap\s*\)\s*\{)",
            lsrc,
        )
        if m:
            start_brace = m.end() - 1
            depth = 1
            pos = start_brace + 1
            while pos < len(lsrc) and depth > 0:
                if lsrc[pos] == "{":
                    depth += 1
                elif lsrc[pos] == "}":
                    depth -= 1
                pos += 1
            if depth == 0:
                inner = lsrc[start_brace + 1 : pos - 1]
                wrapped = (
                    "{\n        try {"
                    + inner
                    + "\n        } catch (const std::exception & e) {\n"
                    '            LLAMA_LOG_WARN("%s: mmap failed (%s); falling back to read I/O\\n", __func__, e.what());\n'
                    "            mappings.clear();\n"
                    "            mmaps_used.clear();\n"
                    "            use_mmap = false;\n"
                    "        }\n    }"
                )
                lsrc = lsrc[:start_brace] + wrapped + lsrc[pos:]
    loader_cpp.write_text(lsrc, encoding="utf-8")


def inject_openssl_for_wasm(
    wrksrc: pathlib.Path,
    wrkbuild: pathlib.Path,
    obsd_root: pathlib.Path,
    ver: str,
) -> None:
    """
    Configure CMake FindOpenSSL against OpenBSD base LibreSSL headers in `include-root-<ver>`
    using empty stub `.a` archives + `ldflags = ["-lssl", "-lcrypto"]` so `obsd-c++` keeps
    base OpenBSD libc/libssl/libcrypto symbols undefined until final guest merge (never
    pulling a duplicate private copy of `libc`/`_static_tls_align` into `llama.o`).
    """
    wasm_dir = obsd_root / f"build/wasm-{ver}"
    inc_dir = wasm_dir / f"include-root-{ver}"
    stub_dir = wrkbuild / "_obsd_ssl_stub"
    stub_dir.mkdir(parents=True, exist_ok=True)
    ssl_stub = stub_dir / "libssl.a"
    crypto_stub = stub_dir / "libcrypto.a"
    ssl_stub.write_bytes(b"!<arch>\n")
    crypto_stub.write_bytes(b"!<arch>\n")

    cmake_frag = wrksrc / "cmake/obsd-wasm-openssl.cmake"
    cmake_frag.write_text(
        f'list(APPEND CMAKE_FIND_ROOT_PATH "{stub_dir.as_posix()}" "{inc_dir.as_posix()}")\n'
        f'set(OPENSSL_INCLUDE_DIR "{inc_dir.as_posix()}" CACHE PATH "OpenBSD base LibreSSL include" FORCE)\n'
        f'set(OPENSSL_SSL_LIBRARY "{ssl_stub.as_posix()}" CACHE FILEPATH "OpenBSD base libssl stub" FORCE)\n'
        f'set(OPENSSL_CRYPTO_LIBRARY "{crypto_stub.as_posix()}" CACHE FILEPATH "OpenBSD base libcrypto stub" FORCE)\n',
        encoding="utf-8",
    )
    top_cmake = wrksrc / "CMakeLists.txt"
    csrc = top_cmake.read_text(encoding="utf-8")
    inc_line = 'include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/obsd-wasm-openssl.cmake")\n'
    if inc_line not in csrc:
        m = re.search(r"^project\s*\([^\)]+\)\s*$", csrc, flags=re.MULTILINE)
        if not m:
            raise SystemExit("prepare_wasm.py: project(...) not found in top CMakeLists.txt")
        csrc = csrc[: m.end()] + "\n" + inc_line + csrc[m.end() :]
        top_cmake.write_text(csrc, encoding="utf-8")


def prepare_v80(wrksrc: pathlib.Path, wrkbuild: pathlib.Path, ports_root: pathlib.Path) -> None:
    # 1. Extract Svelte Agentic + MCP WebUI dist bundle into $WRKBUILD/tools/ui/dist
    ui_tar = ports_root / ".cache/distfiles/llama.cpp-0.5.0-ui-dist.tar.gz"
    if not ui_tar.is_file():
        raise SystemExit(f"prepare_wasm.py: missing UI distfile {ui_tar}")
    ui_dist = wrkbuild / "tools/ui/dist"
    ui_dist.mkdir(parents=True, exist_ok=True)
    with tarfile.open(ui_tar, "r:gz") as tf:
        tf.extractall(path=ui_dist, filter="data")
    (wrkbuild / "tools/ui/.ui-stamp").write_text("ggml-org/llama-ui|b11146\n", encoding="utf-8")

    # 2. Trim unused tools subdirectories (keep only the *-impl libs needed by unified `llama`)
    tools_cmake = wrksrc / "tools/CMakeLists.txt"
    tools_cmake.write_text(
        "find_package(Threads REQUIRED)\n"
        "llama_add_compile_flags()\n"
        "add_subdirectory(mtmd)\n"
        "add_subdirectory(batched-bench)\n"
        "add_subdirectory(llama-bench)\n"
        "add_subdirectory(completion)\n"
        "add_subdirectory(perplexity)\n"
        "add_subdirectory(quantize)\n"
        "add_subdirectory(fit-params)\n"
        "if (LLAMA_BUILD_SERVER)\n"
        "    add_subdirectory(ui)\n"
        "    add_subdirectory(cli)\n"
        "    add_subdirectory(server)\n"
        "endif()\n",
        encoding="utf-8",
    )

    # 3. Rewrite simple-chat, embedding, and gguf entrypoints and link them into unified `llama-app`
    rewrite_main_entry(wrksrc / "examples/simple-chat/simple-chat.cpp", "llama_simple_chat_entry")
    rewrite_main_entry(wrksrc / "examples/embedding/embedding.cpp", "llama_embedding_entry")
    rewrite_main_entry(wrksrc / "examples/gguf/gguf.cpp", "llama_gguf_entry")

    app_cmake = wrksrc / "app/CMakeLists.txt"
    app_src = app_cmake.read_text(encoding="utf-8")
    if "llama_simple_chat_obj" not in app_src:
        extra_objs = (
            "add_library(llama_simple_chat_obj OBJECT ../examples/simple-chat/simple-chat.cpp)\n"
            "target_link_libraries(llama_simple_chat_obj PRIVATE llama)\n"
            "target_compile_features(llama_simple_chat_obj PRIVATE cxx_std_17)\n"
            "add_library(llama_embedding_obj OBJECT ../examples/embedding/embedding.cpp)\n"
            "target_link_libraries(llama_embedding_obj PRIVATE llama-common llama)\n"
            "target_compile_features(llama_embedding_obj PRIVATE cxx_std_17)\n"
            "add_library(llama_gguf_obj OBJECT ../examples/gguf/gguf.cpp)\n"
            "target_link_libraries(llama_gguf_obj PRIVATE ggml)\n"
            "target_compile_features(llama_gguf_obj PRIVATE cxx_std_17)\n\n"
        )
        app_src = extra_objs + app_src.replace(
            "add_executable(${TARGET} llama.cpp download.cpp)",
            "add_executable(${TARGET} llama.cpp download.cpp $<TARGET_OBJECTS:llama_simple_chat_obj> $<TARGET_OBJECTS:llama_embedding_obj> $<TARGET_OBJECTS:llama_gguf_obj>)",
            1,
        )
        app_cmake.write_text(app_src, encoding="utf-8")

    # 4. Add argv[0] multi-call dispatch + simple-chat/embedding/gguf subcommands to app/llama.cpp
    app_cpp = wrksrc / "app/llama.cpp"
    lcpp = app_cpp.read_text(encoding="utf-8")
    if "llama_simple_chat_entry" not in lcpp:
        decls = (
            'extern "C" int llama_simple_chat_entry(int argc, char ** argv);\n'
            'extern "C" int llama_embedding_entry(int argc, char ** argv);\n'
            'extern "C" int llama_gguf_entry(int argc, char ** argv);\n'
        )
        lcpp = lcpp.replace("int llama_download(int argc, char ** argv);", "int llama_download(int argc, char ** argv);\n" + decls, 1)
        lcpp = lcpp.replace(
            '    {"perplexity",    "Compute model perplexity and KL divergence",         {},           true,          llama_perplexity   },',
            '    {"perplexity",    "Compute model perplexity and KL divergence",         {},           true,          llama_perplexity   },\n'
            '    {"simple-chat",   "Minimal interactive chat example",                   {},           true,          llama_simple_chat_entry},\n'
            '    {"embedding",     "Generate text embeddings",                           {},           true,          llama_embedding_entry},\n'
            '    {"gguf",          "Inspect or write GGUF metadata and tensors",         {},           true,          llama_gguf_entry   },',
            1,
        )
        argv0_dispatch = """int main(int argc, char ** argv) {
    progname = argv[0];
    if (progname != nullptr) {
        std::string bname(progname);
        auto slash = bname.find_last_of('/');
        if (slash != std::string::npos) {
            bname = bname.substr(slash + 1);
        }
        if (bname == "llama-server") {
            setenv("LLAMA_APP_CMD", "serve", 1);
            return llama_server(argc, argv);
        }
        if (bname == "llama-cli") {
            return llama_cli(argc, argv);
        }
        if (bname == "llama-bench") {
            return llama_bench(argc, argv);
        }
        if (bname == "llama-batched-bench") {
            return llama_batched_bench(argc, argv);
        }
        if (bname == "llama-quantize") {
            return llama_quantize(argc, argv);
        }
        if (bname == "llama-completion") {
            return llama_completion(argc, argv);
        }
        if (bname == "llama-perplexity") {
            return llama_perplexity(argc, argv);
        }
        if (bname == "llama-fit-params") {
            return llama_fit_params(argc, argv);
        }
        if (bname == "llama-simple-chat") {
            return llama_simple_chat_entry(argc, argv);
        }
        if (bname == "llama-embedding") {
            return llama_embedding_entry(argc, argv);
        }
        if (bname == "llama-gguf") {
            return llama_gguf_entry(argc, argv);
        }
    }"""
        lcpp = lcpp.replace("int main(int argc, char ** argv) {\n    progname = argv[0];", argv0_dispatch, 1)
        app_cpp.write_text(lcpp, encoding="utf-8")


MULTICALL_78_79_CPP = r'''
#include "llama.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

extern "C" {
int llama_cli_entry(int argc, char ** argv);
int llama_server_entry(int argc, char ** argv);
int llama_simple_chat_entry(int argc, char ** argv);
int llama_embedding_entry(int argc, char ** argv);
int llama_quantize_entry(int argc, char ** argv);
int llama_gguf_entry(int argc, char ** argv);
int llama_bench_entry(int argc, char ** argv);
}

static std::string base_name(const char * p) {
    if (!p) return "llama";
    std::string s(p);
    auto pos = s.find_last_of('/');
    return pos == std::string::npos ? s : s.substr(pos + 1);
}

static int print_help(const char * prog) {
    std::printf(
        "Usage: %s <command> [options]\n\n"
        "Available commands:\n"
        "  cli          Command-line LLM inference & interactive chat (llama-cli)\n"
        "  serve        OpenAI-compatible HTTP API server (llama-server)\n"
        "  bench        Benchmark prompt & generation speed (llama-bench)\n"
        "  quantize     Quantize GGUF model weights (llama-quantize)\n"
        "  embedding    Compute vector embeddings (llama-embedding)\n"
        "  simple-chat  Minimal chat completion runner (llama-simple-chat)\n"
        "  gguf         Read/write/inspect GGUF files (llama-gguf)\n",
        prog ? prog : "llama"
    );
    return 0;
}

int main(int argc, char ** argv) {
    const std::string b = base_name(argc > 0 ? argv[0] : "llama");
    if (b == "llama-cli")         return llama_cli_entry(argc, argv);
    if (b == "llama-server")      return llama_server_entry(argc, argv);
    if (b == "llama-simple-chat") return llama_simple_chat_entry(argc, argv);
    if (b == "llama-embedding")   return llama_embedding_entry(argc, argv);
    if (b == "llama-quantize")    return llama_quantize_entry(argc, argv);
    if (b == "llama-gguf")        return llama_gguf_entry(argc, argv);
    if (b == "llama-bench")       return llama_bench_entry(argc, argv);

    if (argc < 2) {
        return print_help(argv[0]);
    }
    const std::string sub(argv[1]);
    if (sub == "help" || sub == "--help" || sub == "-h") {
        return print_help(argv[0]);
    }
    if (sub == "version" || sub == "--version" || sub == "-v") {
        std::printf("%s\n", llama_print_system_info());
        return 0;
    }
    if (sub == "cli" || sub == "client")    return llama_cli_entry(argc - 1, argv + 1);
    if (sub == "serve" || sub == "server")  return llama_server_entry(argc - 1, argv + 1);
    if (sub == "simple-chat")               return llama_simple_chat_entry(argc - 1, argv + 1);
    if (sub == "embedding")                 return llama_embedding_entry(argc - 1, argv + 1);
    if (sub == "quantize")                  return llama_quantize_entry(argc - 1, argv + 1);
    if (sub == "gguf")                      return llama_gguf_entry(argc - 1, argv + 1);
    if (sub == "bench")                     return llama_bench_entry(argc - 1, argv + 1);

    std::fprintf(stderr, "error: unknown command '%s'\n", sub.c_str());
    return 1;
}
'''


def convert_exec_cmake_to_object(cmake_path: pathlib.Path, exec_name: str, obj_name: str) -> None:
    src = cmake_path.read_text(encoding="utf-8")
    if obj_name in src:
        return
    # Match either set(TARGET <exec_name>) ... add_executable(${TARGET} ...) or direct add_executable
    lines = src.splitlines()
    out = []
    in_target = False
    for ln in lines:
        stripped = ln.strip()
        if stripped == f"set(TARGET {exec_name})":
            out.append(f"set(TARGET {obj_name})")
            in_target = True
            continue
        if in_target and stripped.startswith("add_executable(${TARGET}"):
            out.append(ln.replace("add_executable(${TARGET}", "add_library(${TARGET} OBJECT", 1))
            continue
        if in_target and stripped.startswith("install(TARGETS ${TARGET}"):
            continue
        out.append(ln)
    cmake_path.write_text("\n".join(out) + "\n", encoding="utf-8")


def prepare_v78_v79(wrksrc: pathlib.Path, ver: str) -> None:
    cli_subdir = "main" if ver == "7.8" else "cli"
    cli_cpp = wrksrc / f"tools/{cli_subdir}/{cli_subdir}.cpp"

    rewrite_main_entry(cli_cpp, "llama_cli_entry")
    rewrite_main_entry(wrksrc / "tools/server/server.cpp", "llama_server_entry")
    rewrite_main_entry(wrksrc / "tools/quantize/quantize.cpp", "llama_quantize_entry")
    rewrite_main_entry(wrksrc / "tools/llama-bench/llama-bench.cpp", "llama_bench_entry")
    rewrite_main_entry(wrksrc / "examples/simple-chat/simple-chat.cpp", "llama_simple_chat_entry")
    rewrite_main_entry(wrksrc / "examples/embedding/embedding.cpp", "llama_embedding_entry")
    rewrite_main_entry(wrksrc / "examples/gguf/gguf.cpp", "llama_gguf_entry")

    convert_exec_cmake_to_object(wrksrc / f"tools/{cli_subdir}/CMakeLists.txt", "llama-cli", "llama_cli_obj")
    convert_exec_cmake_to_object(wrksrc / "tools/server/CMakeLists.txt", "llama-server", "llama_server_obj")
    convert_exec_cmake_to_object(wrksrc / "tools/quantize/CMakeLists.txt", "llama-quantize", "llama_quantize_obj")
    convert_exec_cmake_to_object(wrksrc / "tools/llama-bench/CMakeLists.txt", "llama-bench", "llama_bench_obj")
    convert_exec_cmake_to_object(wrksrc / "examples/simple-chat/CMakeLists.txt", "llama-simple-chat", "llama_simple_chat_obj")
    convert_exec_cmake_to_object(wrksrc / "examples/embedding/CMakeLists.txt", "llama-embedding", "llama_embedding_obj")
    convert_exec_cmake_to_object(wrksrc / "examples/gguf/CMakeLists.txt", "llama-gguf", "llama_gguf_obj")

    # Trim examples/CMakeLists.txt to ONLY simple-chat, embedding, gguf
    (wrksrc / "examples/CMakeLists.txt").write_text(
        "find_package(Threads REQUIRED)\n"
        "llama_add_compile_flags()\n"
        "add_subdirectory(simple-chat)\n"
        "add_subdirectory(embedding)\n"
        "add_subdirectory(gguf)\n",
        encoding="utf-8",
    )

    mc_dir = wrksrc / "tools/multicall"
    mc_dir.mkdir(parents=True, exist_ok=True)
    (mc_dir / "llama_multicall.cpp").write_text(MULTICALL_78_79_CPP, encoding="utf-8")

    extra_libs = "server-context common mtmd llama ggml cpp-httplib" if ver == "7.9" else "common mtmd llama ggml"
    (mc_dir / "CMakeLists.txt").write_text(
        "add_executable(llama-app\n"
        "    llama_multicall.cpp\n"
        "    $<TARGET_OBJECTS:llama_cli_obj>\n"
        "    $<TARGET_OBJECTS:llama_server_obj>\n"
        "    $<TARGET_OBJECTS:llama_simple_chat_obj>\n"
        "    $<TARGET_OBJECTS:llama_embedding_obj>\n"
        "    $<TARGET_OBJECTS:llama_quantize_obj>\n"
        "    $<TARGET_OBJECTS:llama_gguf_obj>\n"
        "    $<TARGET_OBJECTS:llama_bench_obj>\n"
        ")\n"
        "set_target_properties(llama-app PROPERTIES OUTPUT_NAME llama)\n"
        "target_compile_features(llama-app PRIVATE cxx_std_17)\n"
        f"target_link_libraries(llama-app PRIVATE {extra_libs} ${{CMAKE_THREAD_LIBS_INIT}})\n"
        "install(TARGETS llama-app RUNTIME)\n",
        encoding="utf-8",
    )

    # Keep only needed subdirs in tools/CMakeLists.txt (note: examples runs before tools in top CMakeLists.txt!)
    (wrksrc / "tools/CMakeLists.txt").write_text(
        "find_package(Threads REQUIRED)\n"
        "llama_add_compile_flags()\n"
        "add_subdirectory(mtmd)\n"
        "add_subdirectory(server)\n"
        f"add_subdirectory({cli_subdir})\n"
        "add_subdirectory(quantize)\n"
        "add_subdirectory(llama-bench)\n"
        "add_subdirectory(multicall)\n",
        encoding="utf-8",
    )


def post_install_symlinks(stage_dir: pathlib.Path, ver: str) -> None:
    bin_dir = stage_dir / "usr/local/bin"
    llama_bin = bin_dir / "llama"
    if not llama_bin.is_file():
        raise SystemExit(f"prepare_wasm.py: missing staged {llama_bin}")

    if ver == "8.0":
        keep_aliases = [
            "llama-cli",
            "llama-server",
            "llama-bench",
            "llama-batched-bench",
            "llama-quantize",
            "llama-completion",
            "llama-perplexity",
            "llama-fit-params",
            "llama-simple-chat",
            "llama-embedding",
            "llama-gguf",
        ]
    else:
        keep_aliases = [
            "llama-cli",
            "llama-server",
            "llama-simple-chat",
            "llama-embedding",
            "llama-quantize",
            "llama-gguf",
            "llama-bench",
        ]

    # Remove standalone duplicate binaries built by tools/mtmd etc. and point all aliases -> llama
    for ent in list(bin_dir.iterdir()):
        if ent.name.startswith("llama-") and ent.name != "llama":
            ent.unlink()
    for alias in keep_aliases:
        os.symlink("llama", bin_dir / alias)


def patch_openbsd_home_fallback(wrksrc: pathlib.Path) -> None:
    """
    Upstream `common/common.cpp` only enables the `getpwuid(getuid())` fallback under
    `#if defined(__linux__)`, throwing `std::runtime_error("Failed to find $HOME directory")`
    on OpenBSD whenever `$HOME` is unset (e.g. rc.d daemons, cron, or clean subshells).
    Enable `getpwuid(getuid())` on `__OpenBSD__` and fall back to `/tmp` if `/etc/passwd` is absent.
    """
    common_cpp = wrksrc / "common/common.cpp"
    if not common_cpp.is_file():
        return
    src = common_cpp.read_text(encoding="utf-8")
    src = src.replace(
        "#if defined(__linux__)\n#include <sys/types.h>\n#include <pwd.h>\n#endif",
        "#if defined(__linux__) || defined(__OpenBSD__)\n#include <sys/types.h>\n#include <pwd.h>\n#endif",
    )
    src = src.replace(
        "#if defined(__linux__)\n#include <pwd.h>\n#endif",
        "#if defined(__linux__) || defined(__OpenBSD__)\n#include <sys/types.h>\n#include <pwd.h>\n#endif",
    )
    src = src.replace(
        "#if defined(__linux__)\n            /* no $HOME is defined, fallback to getpwuid */",
        "#if defined(__linux__) || defined(__OpenBSD__)\n            /* no $HOME is defined, fallback to getpwuid */",
    )
    src = src.replace(
        "#if defined(__linux__)\n        /* no $HOME is defined, fallback to getpwuid */",
        "#if defined(__linux__) || defined(__OpenBSD__)\n        /* no $HOME is defined, fallback to getpwuid */",
    )
    src = src.replace(
        '            if ((!pw) || (!pw->pw_dir)) {\n                throw std::runtime_error("Failed to find $HOME directory");\n            }\n\n            cache_directory = std::string(pw->pw_dir) + std::string("/.cache/");',
        '            const char * home_dir = (pw && pw->pw_dir && pw->pw_dir[0]) ? pw->pw_dir : "/tmp";\n            cache_directory = std::string(home_dir) + std::string("/.cache/");',
    )
    src = src.replace(
        '        if ((!pw) || (!pw->pw_dir)) {\n            throw std::runtime_error("Failed to find $HOME directory");\n        }\n\n        config_directory = std::string(pw->pw_dir) + std::string("/.config/");',
        '        const char * home_dir = (pw && pw->pw_dir && pw->pw_dir[0]) ? pw->pw_dir : "/tmp";\n        config_directory = std::string(home_dir) + std::string("/.config/");',
    )
    common_cpp.write_text(src, encoding="utf-8")


def patch_xxhash_wasm(wrksrc: pathlib.Path) -> None:
    """
    Upstream xxhash.h assumes `defined(__wasm_simd128__) && __has_include(<arm_neon.h>)`
    implies Emscripten's SIMDe polyfill is active. With pure OpenBSD sysroot + Clang 24,
    Clang's real `<arm_neon.h>` exists in resource headers and `#error`s on non-ARM targets.
    """
    for xxh in wrksrc.rglob("xxhash.h"):
        src = xxh.read_text(encoding="utf-8")
        new_src = src.replace(
            "(defined(__wasm_simd128__) && XXH_HAS_INCLUDE(<arm_neon.h>))",
            "0",
        )
        if new_src != src:
            xxh.write_text(new_src, encoding="utf-8")


def main() -> None:
    ver = os.environ["OPENBSD_VERSION"].strip()
    if "--post-install" in sys.argv:
        post_install_symlinks(pathlib.Path(os.environ["STAGE_DIR"]), ver)
        return

    wrksrc = pathlib.Path(os.environ["WRKSRC"])
    wrkbuild = pathlib.Path(os.environ["WRKBUILD"])
    obsd_root = pathlib.Path(os.environ["LIBOBSDCOMPAT_ROOT"])
    ports_root = pathlib.Path(os.environ["OBSD_PORTS_ROOT"])

    patch_mmap_fallback(wrksrc)
    patch_openbsd_home_fallback(wrksrc)
    patch_xxhash_wasm(wrksrc)
    if ver in ("7.9", "8.0"):
        inject_openssl_for_wasm(wrksrc, wrkbuild, obsd_root, ver)
    if ver == "8.0":
        prepare_v80(wrksrc, wrkbuild, ports_root)
    else:
        prepare_v78_v79(wrksrc, ver)


if __name__ == "__main__":
    main()
