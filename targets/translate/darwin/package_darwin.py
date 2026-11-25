#!/usr/bin/env python3
"""
package_darwin.py -- `translate/darwin` (`macosx`) packaging adapter for `obsd-ports`.

Consumes staged port outputs under `build/openbsd/<ver>/translate/darwin-macosx/stage/`
and `built-ports.json`, producing:
  1. `bin/<sym>`: stripped (`strip -x`), two-level-namespace-verified, host-dylib-free,
     and validly ad-hoc signed (`codesign -f -s -`) arm64 Mach-O standalone binaries.
  2. `standalone.tsv`: `<name>\t<guest_path>\t<sym>\t<abs_bin_path>` (multi-call
     aliases point to the same `<abs_bin_path>` so `stage-rootfs.py` hardlinks them
     in `system.aar` by SHA-256).
  3. `ports-applets.tsv`: `<sym>\t<guest_path>\tobsd_tool_main\tbin/<sym>`.
  4. `sysroot/usr/local/...` + `ports-owners.db` + `ports-owners.tsv`.
  5. `packages/<pkgname>.tgz` + `packages/index.tsv`.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Sequence, Set, Tuple

TARGETS_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(TARGETS_ROOT / "common") not in sys.path:
    sys.path.insert(0, str(TARGETS_ROOT / "common"))

import packaging as common_pkg  # noqa: E402


def die(msg: str) -> "NoReturn":
    sys.stderr.write(f"package_darwin (translate): {msg}\n")
    raise SystemExit(1)


def verify_and_sign_macho(bin_path: pathlib.Path, sdk: str) -> None:
    if not common_pkg.is_macho_file(bin_path):
        die(f"{bin_path}: not a Mach-O binary")

    # Strip non-global/debug symbols to keep system.aar compact
    subprocess.run(
        ["/usr/bin/xcrun", "--sdk", sdk, "strip", "-x", str(bin_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )

    # Verify dynamic imports: zero Homebrew / /usr/local / host libc++.1.dylib leaks
    otool_out = subprocess.check_output(
        ["/usr/bin/xcrun", "--sdk", sdk, "otool", "-L", str(bin_path)],
        text=True,
    )
    for ln in otool_out.splitlines()[1:]:
        dep = ln.strip().split(" (", 1)[0]
        if not dep:
            continue
        if "libc++" in dep or not (
            dep.startswith("/usr/lib/libSystem") or dep.startswith("/System/Library/Frameworks/")
        ):
            die(f"{bin_path}: forbidden dynamic library dependency '{dep}'")

    # Verify MH_TWOLEVEL (0x80) and !MH_FORCE_FLAT (0x100)
    hdr_out = subprocess.check_output(
        ["/usr/bin/xcrun", "--sdk", sdk, "otool", "-h", str(bin_path)],
        text=True,
    )
    checked_hdr = False
    for ln in hdr_out.splitlines():
        toks = ln.split()
        if toks and toks[0].startswith("0x"):
            flags = int(toks[-1], 16)
            if (flags & 0x80) == 0 or (flags & 0x100) != 0:
                die(f"{bin_path}: Mach-O header lacks MH_TWOLEVEL or sets MH_FORCE_FLAT (flags=0x{flags:x})")
            checked_hdr = True
    if not checked_hdr:
        die(f"{bin_path}: could not parse Mach-O header flags")

    bin_path.chmod(0o755)
    subprocess.run(
        ["/usr/bin/codesign", "--force", "--sign", "-", str(bin_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True,
    )
    subprocess.run(
        ["/usr/bin/codesign", "--verify", "--verbose=1", str(bin_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True,
    )


def package_translate_binaries(
    lane_dir: pathlib.Path,
    stage_dir: pathlib.Path,
    records: Sequence[Dict[str, Any]],
    sdk: str,
) -> Tuple[List[Tuple[str, str, str, str]], Set[str]]:
    bin_dir = lane_dir / "bin"
    if bin_dir.exists():
        shutil.rmtree(bin_dir)
    bin_dir.mkdir(parents=True, exist_ok=True)

    standalone_rows: List[Tuple[str, str, str, str]] = []
    tsv_rows: List[Tuple[str, str, str, str]] = []
    applet_guest_paths: Set[str] = set()
    seen_syms: Set[str] = set()

    for rec in records:
        for app in rec.get("applets", []):
            sym, staged_bin, paths = common_pkg.resolve_applet_spec(stage_dir, rec, app, seen_syms, die)
            out_bin = (bin_dir / sym).resolve()
            shutil.copy2(staged_bin, out_bin)
            verify_and_sign_macho(out_bin, sdk)

            rel_obj = f"bin/{sym}"
            for gp in paths:
                name = os.path.basename(gp)
                applet_guest_paths.add(gp)
                standalone_rows.append((name, gp, sym, str(out_bin)))
                tsv_rows.append((sym, gp, "obsd_tool_main", rel_obj))

    standalone_rows.sort(key=lambda r: (r[1], r[0]))
    tsv_rows.sort(key=lambda r: (r[1], r[0]))

    standalone_lines = ["# name\tguest_path\ttarget\tbin_path"] + [
        f"{nm}\t{gp}\t{tgt}\t{bp}" for nm, gp, tgt, bp in standalone_rows
    ]
    (lane_dir / "standalone.tsv").write_text("\n".join(standalone_lines) + "\n", encoding="utf-8")

    applet_lines = ["# sym\tguest_path\tentry_sym\tobj_path"] + [
        f"{sym}\t{gp}\t{ent}\t{obj}" for sym, gp, ent, obj in tsv_rows
    ]
    (lane_dir / "ports-applets.tsv").write_text("\n".join(applet_lines) + "\n", encoding="utf-8")
    return tsv_rows, applet_guest_paths


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--openbsd-version", required=True)
    ap.add_argument("--backend", default="translate")
    ap.add_argument("--pal", default="darwin")
    ap.add_argument("--sdk", default="macosx")
    ap.add_argument("--libobsdcompat-root", required=True)
    ap.add_argument("--lane-dir", required=True)
    ap.add_argument("--manifest", required=True)
    args = ap.parse_args()

    lane_dir = pathlib.Path(args.lane_dir).resolve()
    stage_dir = lane_dir / "stage"
    stage_dir.mkdir(parents=True, exist_ok=True)
    records = json.loads(pathlib.Path(args.manifest).read_text(encoding="utf-8"))

    tsv_rows, applet_guest_paths = package_translate_binaries(
        lane_dir=lane_dir,
        stage_dir=stage_dir,
        records=records,
        sdk=args.sdk or "macosx",
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
        f"[package/{args.openbsd_version}/translate/darwin-{args.sdk or 'macosx'}] packaged {pkg_count} port(s) -> "
        f"{len(tsv_rows)} standalone path(s), {copied_files} /usr/local file(s), {owner_count} owner records in {lane_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
