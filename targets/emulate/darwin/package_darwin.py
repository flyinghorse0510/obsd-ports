#!/usr/bin/env python3
"""
package_darwin.py -- `emulate/darwin` (`iphonesimulator` & `iphoneos`) packaging
adapter for `obsd-ports`.

Consumes staged port outputs under `build/openbsd/<ver>/emulate/darwin-<sdk>/stage/`
and `built-ports.json`, producing:
  1. `applets/<sym>.o` + `applets/<sym>.meta.json`: localized Mach-O arm64
     relocatable applet partials (`_obsd_applet_<sym>_main` sole exported symbol,
     zero `(common)` tentative definitions, zero Mach-O TLV `__thread_*` sections,
     zero `__TEXT,__gcc_except_tab` sections [moved to `__TEXT,__const` ->
     `__GUEST_RODATA,__const`], and zero `__DATA,__mod_init_func` sections —
     static constructors retyped via `libobsdcompat`'s `retype_guest_initializers.py`
     and invoked per-exec inside `obsd_applet_<sym>_main` with zero undefined
     `section$start` symbols).
  2. `ports-test-applets.tsv`: `# libobsdcompat.emulate-product-test-applets-v1`
     rows (`port_<ident>\t<guest_path>\t<sym>.c\tobsd_applet_<sym>_main\t-\t-\t-\tports/<port>#<sym>`).
  3. `ports-applets.tsv`: `<sym>\t<guest_path>\tobsd_applet_<sym>_main\tapplets/<sym>.o`.
  4. `sysroot/usr/local/...` + `ports-owners.db` + `ports-owners.tsv`.
  5. `packages/<pkgname>.tgz` + `packages/index.tsv`.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

TARGETS_ROOT = pathlib.Path(__file__).resolve().parents[2]
REPO_ROOT = TARGETS_ROOT.parent
if str(TARGETS_ROOT / "common") not in sys.path:
    sys.path.insert(0, str(TARGETS_ROOT / "common"))
if str(REPO_ROOT / "sdk/lib") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "sdk/lib"))

import packaging as common_pkg  # noqa: E402
import obsd_toolchain as ot  # noqa: E402


def die(msg: str) -> "NoReturn":
    sys.stderr.write(f"package_darwin (emulate): {msg}\n")
    raise SystemExit(1)


def detect_macho_main_symbol(sdk: str, obj_path: pathlib.Path, explicit_entry: str, env: Dict[str, str]) -> str:
    if explicit_entry and explicit_entry != "auto":
        return explicit_entry if explicit_entry.startswith("_") else f"_{explicit_entry}"
    out = subprocess.check_output(
        ["/usr/bin/xcrun", "--sdk", sdk, "nm", "-m", str(obj_path)],
        text=True,
        env=env,
    )
    defs: Set[str] = set()
    for ln in out.splitlines():
        s = ln.strip()
        if "(__TEXT," in s and " external " in f" {s} " and "non-external" not in s and "(undefined)" not in s:
            defs.add(s.split()[-1])
    for cand in ("_obsd_tool_main", "_main", "___main_argc_argv"):
        if cand in defs:
            return cand
    die(f"{obj_path}: no _main or _obsd_tool_main found in Mach-O global symbols (found: {sorted(defs)[:15]})")


def make_unique_port_ident(guest_path: str, used_idents: Set[str]) -> str:
    base = os.path.basename(guest_path)
    sanitized = re.sub(r"[^A-Za-z0-9_]", "_", base)
    cand = f"port_{sanitized}"
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", cand):
        cand = "port_" + re.sub(r"[^A-Za-z0-9_]", "_", guest_path.strip("/"))
    if cand not in used_idents:
        used_idents.add(cand)
        return cand
    full_sanitized = "port_" + re.sub(r"[^A-Za-z0-9_]", "_", guest_path.strip("/"))
    if full_sanitized not in used_idents:
        used_idents.add(full_sanitized)
        return full_sanitized
    idx = 2
    while f"{cand}_{idx}" in used_idents:
        idx += 1
    final = f"{cand}_{idx}"
    used_idents.add(final)
    return final


def localize_darwin_emulate_applets(
    obsd_root: pathlib.Path,
    openbsd_version: str,
    sdk: str,
    lane_dir: pathlib.Path,
    stage_dir: pathlib.Path,
    records: Sequence[Dict[str, Any]],
) -> Tuple[List[Tuple[str, str, str, str]], Set[str]]:
    retype_dir = obsd_root / "tools/build/personalities/openbsd/backends/translate"
    if str(retype_dir) not in sys.path:
        sys.path.insert(0, str(retype_dir))
    import retype_guest_initializers as rgi  # type: ignore

    tc = ot.DarwinToolchain(
        openbsd_version=openbsd_version,
        backend="emulate",
        sdk=sdk,
        obsd_root=obsd_root,
        stage_dir=stage_dir,
    )
    senv = tc.sanitized_env()
    target_flags = shlex.split(tc.emulate_info["target_flags"])
    objcopy = tc.find_llvm_objcopy()
    cc = tc.cc_cmd

    applets_dir = lane_dir / "applets"
    if applets_dir.exists():
        shutil.rmtree(applets_dir)
    applets_dir.mkdir(parents=True, exist_ok=True)

    shared_dir = lane_dir / "shared"
    if shared_dir.exists():
        shutil.rmtree(shared_dir)
    shared_dir.mkdir(parents=True, exist_ok=True)

    cxx_rt_syms = tc.darwin_cxx_rt_defined_symbols()
    needed_cxx_rt_syms: Set[str] = set()

    tsv_rows: List[Tuple[str, str, str, str]] = []
    test_applet_lines: List[str] = ["# libobsdcompat.emulate-product-test-applets-v1"]
    applet_guest_paths: Set[str] = set()
    seen_syms: Set[str] = set()
    used_idents: Set[str] = set()

    with tempfile.TemporaryDirectory(prefix=f"obsd-emulate-pkg-{openbsd_version}-{sdk}-") as td:
        tp = pathlib.Path(td)

        for rec in records:
            for app in rec.get("applets", []):
                sym, bin_path, paths = common_pkg.resolve_applet_spec(stage_dir, rec, app, seen_syms, die)
                if not common_pkg.is_macho_file(bin_path):
                    die(f"applet '{sym}' ({rec['port']}): {bin_path} is not a Mach-O relocatable object")

                work_o = tp / f"{sym}.work.o"
                extra_inputs = [str(stage_dir / x.lstrip("/")) for x in app.get("extra_libs", [])]
                if extra_inputs:
                    subprocess.run(
                        [*cc, *target_flags, "-arch", "arm64", "-nostdlib", "-Wl,-r,-S,-keep_private_externs", str(bin_path), *extra_inputs, "-o", str(work_o)],
                        env=senv,
                        check=True,
                    )
                else:
                    shutil.copy2(bin_path, work_o)

                # Realize any tentative (common) definitions inside this applet before localization
                nm_m = subprocess.check_output(["/usr/bin/xcrun", "--sdk", sdk, "nm", "-m", str(work_o)], text=True, env=senv)
                if " (common) " in nm_m:
                    commons_tool = obsd_root / "tools/build/personalities/openbsd/backends/emulate/gen_guest_commons.py"
                    commons_c = tp / f"{sym}.commons.c"
                    commons_o = tp / f"{sym}.commons.o"
                    subprocess.run(["/usr/bin/python3", "-I", "-B", str(commons_tool), "--object", str(work_o), "--output", str(commons_c)], env=senv, check=True)
                    subprocess.run(
                        [*tc.cc_compile_cmd, *target_flags, "-arch", "arm64", "-ffixed-x18", "-fno-omit-frame-pointer", "-fno-stack-protector", "-fno-common", "-O2", "-c", str(commons_c), "-o", str(commons_o)],
                        env=senv,
                        check=True,
                    )
                    merged_o = tp / f"{sym}.nocommon.o"
                    subprocess.run([*cc, *target_flags, "-arch", "arm64", "-nostdlib", "-Wl,-r,-S,-keep_private_externs", str(work_o), str(commons_o), "-o", str(merged_o)], env=senv, check=True)
                    work_o = merged_o

                # Retype & wrap any surviving __DATA,__mod_init_func via retype_guest_initializers.py
                ot.retype_and_wrap_macho_ctors(tc, work_o, tp, target_flags)

                src_entry = detect_macho_main_symbol(sdk, work_o, app.get("entry", "auto"), senv)
                ot.promote_macho_symbol_external(work_o, src_entry)
                target_entry_c = f"obsd_applet_{sym}_main"
                target_entry_macho = f"_{target_entry_c}"

                # Check if applet references OpenBSD libcrypto (needs openssl_init_crypto_constructor)
                undef_out = subprocess.check_output(["/usr/bin/xcrun", "--sdk", sdk, "nm", "-u", str(work_o)], text=True, env=senv)
                needs_crypto_ctor = any(
                    u.startswith(("_SSL_", "_OPENSSL_", "_EVP_", "_CRYPTO_", "_X509_", "_BIO_", "_TLS_"))
                    for u in (ln.strip().split()[-1] for ln in undef_out.splitlines() if ln.strip())
                )

                if needs_crypto_ctor:
                    real_main_macho = f"___obsd_port_real_{sym}_main"
                    real_main_c = f"__obsd_port_real_{sym}_main"
                    subprocess.run([str(objcopy), "--redefine-sym", f"{src_entry}={real_main_macho}", str(work_o)], env=senv, check=True)
                    wrap_c = tp / f"{sym}.crypto_wrap.c"
                    wrap_o = tp / f"{sym}.crypto_wrap.o"
                    wrap_c.write_text(
                        "\n".join(
                            [
                                "extern void openssl_init_crypto_constructor(void);",
                                f"extern int {real_main_c}(int, char **, char **);",
                                f"int {target_entry_c}(int argc, char **argv, char **envp);",
                                f"int {target_entry_c}(int argc, char **argv, char **envp) {{",
                                "\topenssl_init_crypto_constructor();",
                                f"\treturn {real_main_c}(argc, argv, envp);",
                                "}",
                            ]
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                    subprocess.run(
                        [*tc.cc_compile_cmd, *target_flags, "-arch", "arm64", "-ffixed-x18", "-fno-omit-frame-pointer", "-fno-stack-protector", "-fno-common", "-O2", "-c", str(wrap_c), "-o", str(wrap_o)],
                        env=senv,
                        check=True,
                    )
                    link_objs = [str(wrap_o), str(work_o)]
                else:
                    if src_entry != target_entry_macho:
                        subprocess.run([str(objcopy), "--redefine-sym", f"{src_entry}={target_entry_macho}", str(work_o)], env=senv, check=True)
                    link_objs = [str(work_o)]

                exp_file = tp / f"{sym}.exports"
                exp_file.write_text(f"{target_entry_macho}\n", encoding="utf-8")
                loc_obj = applets_dir / f"{sym}.o"
                subprocess.run(
                    [
                        *cc,
                        *target_flags,
                        "-arch",
                        "arm64",
                        "-nostdlib",
                        "-Wl,-r,-S",
                        "-Wl,-rename_section,__TEXT,__gcc_except_tab,__TEXT,__const",
                        f"-Wl,-exported_symbols_list,{exp_file}",
                        *link_objs,
                        "-o",
                        str(loc_obj),
                    ],
                    env=senv,
                    check=True,
                )

                # Verify invariants on applets/<sym>.o:
                # 1. Zero __mod_init_func / __mod_term_func and zero __TEXT,__gcc_except_tab
                final_obj = rgi.read_object(str(loc_obj), loc_obj.name)
                if final_obj.initializer_sections() or final_obj.terminator_sections():
                    die(f"{loc_obj}: un-retyped Mach-O initializer/terminator section survived")
                if any(s.segname == "__TEXT" and s.sectname == "__gcc_except_tab" for s in final_obj.sections):
                    die(f"{loc_obj}: __TEXT,__gcc_except_tab survived (must move to __TEXT,__const)")
                # 2. Zero Mach-O native TLV (__thread_vars / __thread_bss / __thread_data) & zero unbanked __DATA,{__data,__bss,__common}
                tlv_secs = [f"{s.segname},{s.sectname}" for s in final_obj.sections if s.sectname.startswith("__thread_")]
                if tlv_secs:
                    die(f"{loc_obj}: forbidden Mach-O native TLV section(s) found: {tlv_secs}")
                unbanked_secs = [
                    f"{s.segname},{s.sectname}({s.size}B)"
                    for s in final_obj.sections
                    if s.segname == "__DATA" and s.sectname in ("__data", "__bss", "__common") and s.size > 0
                ]
                if unbanked_secs:
                    die(f"{loc_obj}: unbanked mutable __DATA section(s) survived ObsdGuestBankPass: {unbanked_secs}")
                # 3. Zero tentative (common) symbols & sole external export == _obsd_applet_<sym>_main
                nm_loc = subprocess.check_output(["/usr/bin/xcrun", "--sdk", sdk, "nm", "-m", str(loc_obj)], text=True, env=senv)
                if " (common) " in nm_loc:
                    die(f"{loc_obj}: tentative (common) symbol survived localization")
                ext_defs = sorted(
                    ln.split()[-1]
                    for ln in nm_loc.splitlines()
                    if " external " in ln and "(undefined)" not in ln and "non-external" not in ln and "private external" not in ln
                )
                if ext_defs != [target_entry_macho]:
                    die(f"{loc_obj}: expected sole external {target_entry_macho}, got {ext_defs}")

                loc_undefs, _loc_defs = ot.macho_undefined_and_defined(tc, loc_obj)
                needed_cxx_rt_syms |= loc_undefs & cxx_rt_syms

                meta = {
                    "sym": sym,
                    "port": rec["port"],
                    "pkgname": rec["pkgname"],
                    "sdk": sdk,
                    "entry_symbol": target_entry_c,
                    "needs_crypto_ctor": needs_crypto_ctor,
                    "paths": paths,
                }
                (applets_dir / f"{sym}.meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

                rel_obj = f"applets/{sym}.o"
                for gp in paths:
                    applet_guest_paths.add(gp)
                    tsv_rows.append((sym, gp, target_entry_c, rel_obj))
                    ident = make_unique_port_ident(gp, used_idents)
                    test_applet_lines.append(
                        f"{ident}\t{gp}\t{sym}.c\t{target_entry_c}\t-\t-\t-\tports/{rec['port']}#{sym}"
                    )

        # Emit a single shared guest C++ runtime relocatable (`shared/darwin_cxx_rt.o`)
        # when any port applet uses C++, so all C++ port partials share ONE `___gxx_personality_v0`
        # inside `SonvoriBSD_<ver>.framework` (respecting Mach-O `__unwind_info`'s <= 3 personality limit).
        if needed_cxx_rt_syms:
            libcxx_a, libcxxabi_a, libunwind_a, emutls_a = tc.ensure_darwin_cxx_runtime()
            libm_a = tc.ensure_guest_libm_archive()
            force_u_syms = sorted(needed_cxx_rt_syms - {"___obsd_cxx_rt_init"})
            u_flags = [f"-Wl,-u,{s}" for s in force_u_syms]
            rt_raw = tp / "darwin_cxx_rt.raw.o"
            subprocess.run(
                [
                    *cc,
                    *target_flags,
                    "-arch",
                    "arm64",
                    "-nostdlib",
                    "-Wl,-r,-S,-keep_private_externs",
                    *u_flags,
                    str(libcxx_a),
                    str(libcxxabi_a),
                    str(libunwind_a),
                    str(emutls_a),
                    str(libm_a),
                    "-o",
                    str(rt_raw),
                ],
                env=senv,
                check=True,
            )

            rt_mobj = rgi.read_object(str(rt_raw), rt_raw.name)
            has_rt_gi = any(
                s.segname == "__GUEST" and s.sectname in ("__obsd_gi0098", "__obsd_gi0099") and s.size > 0
                for s in rt_mobj.sections
            )
            ctor_c_names = ot.extract_and_expose_retyped_ctors(rt_raw, objcopy, senv) if has_rt_gi else []
            unique_rt_ctors = list(dict.fromkeys(ctor_c_names))

            rt_init_c = tp / "darwin_cxx_rt_init.c"
            rt_init_o = tp / "darwin_cxx_rt_init.o"
            rt_init_c.write_text(
                "\n".join(
                    [
                        "static int __obsd_cxx_rt_inited;",
                        *[f"extern void {cn}(void);" for cn in unique_rt_ctors],
                        "void __obsd_cxx_rt_init(void);",
                        "void __obsd_cxx_rt_init(void) {",
                        "\tif (!__obsd_cxx_rt_inited) {",
                        "\t\t__obsd_cxx_rt_inited = 1;",
                        *[f"\t\t{cn}();" for cn in ctor_c_names],
                        "\t}",
                        "}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            subprocess.run(
                [
                    *tc.cc_compile_cmd,
                    *target_flags,
                    "-arch",
                    "arm64",
                    "-ffixed-x18",
                    "-fno-omit-frame-pointer",
                    "-fno-stack-protector",
                    "-fno-common",
                    "-O2",
                    "-c",
                    str(rt_init_c),
                    "-o",
                    str(rt_init_o),
                ],
                env=senv,
                check=True,
            )

            rt_pre = tp / "darwin_cxx_rt.pre.o"
            subprocess.run(
                [
                    *cc,
                    *target_flags,
                    "-arch",
                    "arm64",
                    "-nostdlib",
                    "-Wl,-r,-S,-keep_private_externs",
                    str(rt_init_o),
                    str(rt_raw),
                    str(emutls_a),
                    str(libm_a),
                    "-o",
                    str(rt_pre),
                ],
                env=senv,
                check=True,
            )

            nm_rt_pre = subprocess.check_output(["/usr/bin/xcrun", "--sdk", sdk, "nm", "-m", str(rt_pre)], text=True, env=senv)
            if " (common) " in nm_rt_pre:
                commons_tool = obsd_root / "tools/build/personalities/openbsd/backends/emulate/gen_guest_commons.py"
                rt_com_c = tp / "darwin_cxx_rt.commons.c"
                rt_com_o = tp / "darwin_cxx_rt.commons.o"
                subprocess.run(["/usr/bin/python3", "-I", "-B", str(commons_tool), "--object", str(rt_pre), "--output", str(rt_com_c)], env=senv, check=True)
                subprocess.run(
                    [*tc.cc_compile_cmd, *target_flags, "-arch", "arm64", "-ffixed-x18", "-fno-omit-frame-pointer", "-fno-stack-protector", "-fno-common", "-O2", "-c", str(rt_com_c), "-o", str(rt_com_o)],
                    env=senv,
                    check=True,
                )
                rt_nc = tp / "darwin_cxx_rt.nocommon.o"
                subprocess.run([*cc, *target_flags, "-arch", "arm64", "-nostdlib", "-Wl,-r,-S,-keep_private_externs", str(rt_pre), str(rt_com_o), "-o", str(rt_nc)], env=senv, check=True)
                rt_pre = rt_nc

            for req_sym in sorted(needed_cxx_rt_syms):
                ot.promote_macho_symbol_external(rt_pre, req_sym)

            rt_undefs, rt_defs = ot.macho_undefined_and_defined(tc, rt_pre)
            missing_rt_exports = sorted(needed_cxx_rt_syms - rt_defs)
            if missing_rt_exports:
                die(f"shared/darwin_cxx_rt.o missing expected C++ runtime symbols: {missing_rt_exports[:15]}")
            disallowed_rt_undefs = sorted(rt_undefs - rt_defs - tc.allowed_guest_undefined_symbols())
            if disallowed_rt_undefs:
                die(f"shared/darwin_cxx_rt.o has disallowed undefined symbols: {disallowed_rt_undefs[:15]}")

            rt_exp_file = tp / "darwin_cxx_rt.exports"
            rt_exp_file.write_text("".join(f"{s}\n" for s in sorted(needed_cxx_rt_syms)), encoding="utf-8")
            shared_rt_o = shared_dir / "darwin_cxx_rt.o"
            subprocess.run(
                [
                    *cc,
                    *target_flags,
                    "-arch",
                    "arm64",
                    "-nostdlib",
                    "-Wl,-r,-S",
                    "-Wl,-rename_section,__TEXT,__gcc_except_tab,__TEXT,__const",
                    f"-Wl,-exported_symbols_list,{rt_exp_file}",
                    str(rt_pre),
                    "-o",
                    str(shared_rt_o),
                ],
                env=senv,
                check=True,
            )

            rt_final = rgi.read_object(str(shared_rt_o), shared_rt_o.name)
            if rt_final.initializer_sections() or rt_final.terminator_sections():
                die(f"{shared_rt_o}: un-retyped Mach-O initializer/terminator section survived")
            if any(s.segname == "__GUEST" and s.sectname.startswith("__obsd_gi") for s in rt_final.sections):
                die(f"{shared_rt_o}: __GUEST,__obsd_gi* section survived")
            if any(s.segname == "__TEXT" and s.sectname == "__gcc_except_tab" for s in rt_final.sections):
                die(f"{shared_rt_o}: __TEXT,__gcc_except_tab survived")
            if any(s.sectname.startswith("__thread_") for s in rt_final.sections):
                die(f"{shared_rt_o}: Mach-O native TLV section survived")
            rt_unbanked = [
                f"{s.segname},{s.sectname}({s.size}B)"
                for s in rt_final.sections
                if s.segname == "__DATA" and s.sectname in ("__data", "__bss", "__common") and s.size > 0
            ]
            if rt_unbanked:
                die(f"{shared_rt_o}: unbanked mutable __DATA section(s) survived: {rt_unbanked}")
            nm_rt_final = subprocess.check_output(["/usr/bin/xcrun", "--sdk", sdk, "nm", "-m", str(shared_rt_o)], text=True, env=senv)
            if " (common) " in nm_rt_final:
                die(f"{shared_rt_o}: tentative (common) symbol survived")
            pers_cnt = sum(1 for ln in nm_rt_final.splitlines() if ln.strip().endswith("___gxx_personality_v0") and "(undefined)" not in ln)
            if pers_cnt > 1:
                die(f"{shared_rt_o}: expected <= 1 ___gxx_personality_v0 definition, got {pers_cnt}")

    tsv_rows.sort(key=lambda r: (r[1], r[0]))
    applet_lines = ["# sym\tguest_path\tentry_sym\tobj_path"] + [
        f"{sym}\t{gp}\t{ent}\t{obj}" for sym, gp, ent, obj in tsv_rows
    ]
    (lane_dir / "ports-applets.tsv").write_text("\n".join(applet_lines) + "\n", encoding="utf-8")
    (lane_dir / "ports-test-applets.tsv").write_text("\n".join(test_applet_lines) + "\n", encoding="utf-8")
    return tsv_rows, applet_guest_paths


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--openbsd-version", required=True)
    ap.add_argument("--backend", default="emulate")
    ap.add_argument("--pal", default="darwin")
    ap.add_argument("--sdk", default="iphonesimulator")
    ap.add_argument("--libobsdcompat-root", required=True)
    ap.add_argument("--lane-dir", required=True)
    ap.add_argument("--manifest", required=True)
    args = ap.parse_args()

    obsd_root = pathlib.Path(args.libobsdcompat_root).resolve()
    lane_dir = pathlib.Path(args.lane_dir).resolve()
    stage_dir = lane_dir / "stage"
    stage_dir.mkdir(parents=True, exist_ok=True)
    records = json.loads(pathlib.Path(args.manifest).read_text(encoding="utf-8"))
    sdk = args.sdk or "iphonesimulator"

    tsv_rows, applet_guest_paths = localize_darwin_emulate_applets(
        obsd_root=obsd_root,
        openbsd_version=args.openbsd_version,
        sdk=sdk,
        lane_dir=lane_dir,
        stage_dir=stage_dir,
        records=records,
    )
    copied_files, owner_count = common_pkg.stage_usr_local_sysroot(
        lane_dir=lane_dir,
        stage_dir=stage_dir,
        tsv_rows=tsv_rows,
        applet_guest_paths=applet_guest_paths,
        is_binary_object=common_pkg.is_macho_file,
        emit_svfs=False,
        record_applet_stubs_in_owners=True,
    )
    pkg_count = common_pkg.emit_port_packages(lane_dir=lane_dir, stage_dir=stage_dir, records=records)

    print(
        f"[package/{args.openbsd_version}/emulate/darwin-{sdk}] packaged {pkg_count} port(s) -> "
        f"{len(tsv_rows)} applet path(s), {copied_files} /usr/local file(s), {owner_count} owner records in {lane_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
