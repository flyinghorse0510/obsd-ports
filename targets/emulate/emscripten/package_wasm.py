#!/usr/bin/env python3
"""
package_wasm.py -- `emulate/emscripten` WASM64 packaging adapter for `obsd-ports`.

Consumes staged port outputs under `build/openbsd/<ver>/emulate/emscripten/stage/`
and `built-ports.json`, producing:
  1. `applets/<sym>.o` + `applets/<sym>.meta.json` (localized WASM64 relocatable
     applet closures via `wasm_object_tool.py localize-applet`).
  2. `ports-applets.tsv` (`<sym>\t<guest_path>\t<entry_sym>\tapplets/<sym>.o`).
  3. `sysroot/usr/local/...` (complete `/usr/local` overlay excluding raw WASM
     applet binaries at `ports-applets.tsv` paths).
  4. `ports.svfs.gz` (SVFS v1 gzip-compressed bundle of `/usr/local/...` with
     applet stubs).
  5. `ports-owners.db` and `ports-owners.tsv`.
  6. `packages/<pkgname>.tgz` + `packages/index.tsv`.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Sequence, Set, Tuple

TARGETS_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(TARGETS_ROOT / "common") not in sys.path:
    sys.path.insert(0, str(TARGETS_ROOT / "common"))

import packaging as common_pkg  # noqa: E402

is_wasm_object = common_pkg.is_wasm_object
resolve_staged_symlink = common_pkg.resolve_staged_symlink
build_fr_record = common_pkg.build_fr_record
emit_port_packages = common_pkg.emit_port_packages


def die(msg: str) -> "NoReturn":
    sys.stderr.write(f"package_wasm: {msg}\n")
    raise SystemExit(1)


def detect_wasm_main_symbol(llvm_nm: pathlib.Path, obj_path: pathlib.Path, explicit_entry: str) -> str:
    if explicit_entry and explicit_entry != "auto":
        return explicit_entry
    out = subprocess.check_output(
        [str(llvm_nm), "--defined-only", "-g", str(obj_path)],
        text=True,
        stderr=subprocess.DEVNULL,
    )
    defs: Set[str] = set()
    for ln in out.splitlines():
        ps = ln.split()
        if len(ps) >= 3 and ps[1] in ("T", "W"):
            defs.add(ps[2])
        elif len(ps) == 2 and ps[0] in ("T", "W"):
            defs.add(ps[1])

    for cand in ("obsd_tool_main", "__main_argc_argv", "main", "__original_main"):
        if cand in defs:
            return cand
    die(f"{obj_path}: no main entrypoint found in WASM global function symbols (found: {sorted(defs)[:15]})")


def localize_port_applets(
    obsd_root: pathlib.Path,
    openbsd_version: str,
    lane_dir: pathlib.Path,
    stage_dir: pathlib.Path,
    records: Sequence[Dict[str, Any]],
) -> Tuple[List[Tuple[str, str, str, str]], Set[str]]:
    emulate_tools = obsd_root / "tools/build/personalities/openbsd/backends/emulate"
    if str(emulate_tools) not in sys.path:
        sys.path.insert(0, str(emulate_tools))
    import build_wasm_guest as bwg  # type: ignore

    wasm_obj_tool = emulate_tools / "wasm_object_tool.py"
    llvm_bin = obsd_root / "deps/emsdk/upstream/bin"
    wasm_ld = llvm_bin / "wasm-ld"
    llvm_nm = llvm_bin / "llvm-nm"

    applets_dir = lane_dir / "applets"
    if applets_dir.exists():
        shutil.rmtree(applets_dir)
    applets_dir.mkdir(parents=True, exist_ok=True)

    tsv_rows: List[Tuple[str, str, str, str]] = []
    applet_guest_paths: Set[str] = set()
    seen_syms: Set[str] = set()

    for rec in records:
        for app in rec.get("applets", []):
            sym, bin_path, paths = common_pkg.resolve_applet_spec(stage_dir, rec, app, seen_syms, die)
            if not is_wasm_object(bin_path):
                die(f"applet '{sym}' ({rec['port']}): {bin_path} is not a WASM64 relocatable binary")

            raw_obj = applets_dir / f"{sym}.raw.o"
            extra_inputs = [str(stage_dir / x.lstrip("/")) for x in app.get("extra_libs", [])]
            if extra_inputs:
                subprocess.run(
                    [str(wasm_ld), "-m", "wasm64", "--fatal-warnings", "-r", str(bin_path), *extra_inputs, "-o", str(raw_obj)],
                    check=True,
                )
            else:
                shutil.copy2(bin_path, raw_obj)

            src_entry = detect_wasm_main_symbol(llvm_nm, raw_obj, app.get("entry", "auto"))
            loc_obj = applets_dir / f"{sym}.o"
            subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(wasm_obj_tool),
                    "localize-applet",
                    "--applet-sym",
                    sym,
                    "--entry-symbol",
                    src_entry,
                    "-i",
                    str(raw_obj),
                    "-o",
                    str(loc_obj),
                ],
                check=True,
            )
            raw_obj.unlink(missing_ok=True)

            target_entry = f"obsd_applet_{sym}_main"
            malloc_sym = f"obsd_applet_{sym}_malloc_options"
            arity, ret_void, has_malloc = bwg.inspect_wasm_applet_signature(loc_obj, target_entry, malloc_sym)
            meta = {
                "sym": sym,
                "port": rec["port"],
                "pkgname": rec["pkgname"],
                "entry_symbol": target_entry,
                "source_entry": src_entry,
                "arity": arity,
                "ret_void": ret_void,
                "has_malloc": has_malloc,
                "paths": paths,
            }
            (applets_dir / f"{sym}.meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

            rel_obj = f"applets/{sym}.o"
            for gp in paths:
                applet_guest_paths.add(gp)
                tsv_rows.append((sym, gp, target_entry, rel_obj))

    tsv_rows.sort(key=lambda r: (r[1], r[0]))
    tsv_path = lane_dir / "ports-applets.tsv"
    lines = ["# sym\tguest_path\tentry_sym\tobj_path"] + [
        f"{sym}\t{gp}\t{ent}\t{obj}" for sym, gp, ent, obj in tsv_rows
    ]
    tsv_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return tsv_rows, applet_guest_paths


def stage_sysroot_and_svfs(
    lane_dir: pathlib.Path,
    stage_dir: pathlib.Path,
    tsv_rows: Sequence[Tuple[str, str, str, str]],
    applet_guest_paths: Set[str],
) -> Tuple[int, int]:
    return common_pkg.stage_usr_local_sysroot(
        lane_dir=lane_dir,
        stage_dir=stage_dir,
        tsv_rows=tsv_rows,
        applet_guest_paths=applet_guest_paths,
        is_binary_object=is_wasm_object,
        emit_svfs=True,
        record_applet_stubs_in_owners=True,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--openbsd-version", required=True)
    ap.add_argument("--backend", default="emulate")
    ap.add_argument("--pal", default="emscripten")
    ap.add_argument("--sdk", default="")
    ap.add_argument("--libobsdcompat-root", required=True)
    ap.add_argument("--lane-dir", required=True)
    ap.add_argument("--manifest", required=True)
    args = ap.parse_args()

    obsd_root = pathlib.Path(args.libobsdcompat_root).resolve()
    lane_dir = pathlib.Path(args.lane_dir).resolve()
    stage_dir = lane_dir / "stage"
    stage_dir.mkdir(parents=True, exist_ok=True)
    records = json.loads(pathlib.Path(args.manifest).read_text(encoding="utf-8"))

    tsv_rows, applet_guest_paths = localize_port_applets(
        obsd_root=obsd_root,
        openbsd_version=args.openbsd_version,
        lane_dir=lane_dir,
        stage_dir=stage_dir,
        records=records,
    )
    copied_files, svfs_count = stage_sysroot_and_svfs(
        lane_dir=lane_dir,
        stage_dir=stage_dir,
        tsv_rows=tsv_rows,
        applet_guest_paths=applet_guest_paths,
    )
    pkg_count = emit_port_packages(lane_dir=lane_dir, stage_dir=stage_dir, records=records)

    print(
        f"[package/{args.openbsd_version}] packaged {pkg_count} port(s) -> "
        f"{len(tsv_rows)} applet path(s), {copied_files} /usr/local file(s), {svfs_count} SVFS entries in {lane_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
