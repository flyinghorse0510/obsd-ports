#!/usr/bin/env python3
"""
import_port.py -- Import unmodified OpenBSD port subtrees (<category>/<port>)
from the SHA256-verified official release `ports.tar.gz` archives into
`vendor/openbsd/versions/<ver>/ports/<category>/<port>/` and record their exact
SHA256 digests in `tools/audit/vendor-baseline.tsv`.

Automatically imports any ancestor `Makefile.inc` / `*.port.mk` files (such as
`lang/lua/Makefile.inc` and `lang/lua/lua.port.mk` for `lang/lua/5.4`) while
excluding CVS metadata directories.
"""
from __future__ import annotations

import argparse
import pathlib
import shutil
import sys
import tarfile
from typing import List, Set

THIS_DIR = pathlib.Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

import sync_openbsd_ports as sync_mod


def normalize_portpath(raw: str) -> str:
    p = raw.strip().strip("/")
    if p.startswith("ports/"):
        p = p[len("ports/") :]
    if not p or "/" not in p or ".." in p.split("/"):
        raise SystemExit(f"invalid port path '{raw}' (expected <category>/<name>, e.g. archivers/bzip2)")
    return p


def import_ports_for_version(
    repo_root: pathlib.Path,
    row: dict,
    portpaths: List[str],
) -> None:
    ver = row["version"]
    tar_path = repo_root / ".cache/openbsd" / ver / "ports.tar.gz"
    sync_mod.download_and_verify(row["ports_url"], tar_path, row["ports_sha256"])

    vendor_ports_dir = repo_root / row["vendor_dir"]
    wanted_prefixes = [f"ports/{p}/" for p in portpaths]
    wanted_ancestor_files: Set[str] = {"ports/infrastructure/db/network.conf"}
    ancestor_dir_prefixes: Set[str] = set()
    for p in portpaths:
        parts = p.split("/")
        for i in range(1, len(parts)):
            anc = "/".join(parts[:i])
            wanted_ancestor_files.add(f"ports/{anc}/Makefile.inc")
            ancestor_dir_prefixes.add(f"ports/{anc}/")

    # Clean existing target port subtrees prior to clean extraction so stale files never linger
    for p in portpaths:
        dest_sub = vendor_ports_dir / p
        if dest_sub.exists():
            shutil.rmtree(dest_sub)

    found_counts = {p: 0 for p in portpaths}
    with tarfile.open(tar_path, "r:gz") as tf:
        for member in tf:
            if not member.isfile():
                continue
            name = member.name
            if "/CVS/" in name or name.endswith("/.cvsignore"):
                continue

            matched_port = None
            for p, pref in zip(portpaths, wanted_prefixes):
                if name.startswith(pref):
                    matched_port = p
                    break

            is_anc = name in wanted_ancestor_files or (
                any(name.startswith(ap) and "/" not in name[len(ap) :] and name.endswith(".port.mk") for ap in ancestor_dir_prefixes)
            )

            if matched_port is None and not is_anc:
                continue

            rel_inside_ports = name[len("ports/") :]
            out_path = vendor_ports_dir / rel_inside_ports
            out_path.parent.mkdir(parents=True, exist_ok=True)
            fp = tf.extractfile(member)
            if fp is None:
                continue
            out_path.write_bytes(fp.read())
            if matched_port is not None:
                found_counts[matched_port] += 1

    missing = [p for p, c in found_counts.items() if c == 0]
    if missing:
        raise SystemExit(
            f"[import-port] OpenBSD {ver}: port(s) not found in official ports.tar.gz: {', '.join(missing)}"
        )
    summary = ", ".join(f"{p} ({found_counts[p]} files)" for p in portpaths)
    print(f"[import-port] OpenBSD {ver}: imported {summary}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--version", default="all", help="OpenBSD release version (7.8, 7.9, or all)")
    ap.add_argument("ports", nargs="+", help="Port path(s) <category>/<name> [...]")
    args = ap.parse_args()

    repo_root = pathlib.Path(__file__).resolve().parents[2]
    portpaths = [normalize_portpath(p) for p in args.ports]
    manifest = sync_mod.load_versions_manifest(repo_root / "config/versions/index.tsv")
    selected = [r for r in manifest if args.version == "all" or r["version"] == args.version]
    if not selected:
        raise SystemExit(f"unknown OpenBSD version '{args.version}'")

    for row in selected:
        import_ports_for_version(repo_root, row, portpaths)

    total = sync_mod.refresh_vendor_baseline(repo_root)
    print(f"[import-port] updated tools/audit/vendor-baseline.tsv ({total} immutable vendor files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
