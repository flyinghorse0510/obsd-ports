#!/usr/bin/env python3
"""
sync_openbsd_ports.py -- Idempotent synchronizer for official OpenBSD release
ports.tar.gz archives (7.8, 7.9, ...).

1. Reads release URLs and pinned SHA256 digests from `config/versions/index.tsv`.
2. Downloads into `.cache/openbsd/<ver>/ports.tar.gz` (if absent) and verifies
   exact SHA256.
3. Extracts `ports/infrastructure/db/network.conf` into
   `vendor/openbsd/versions/<ver>/ports/infrastructure/db/network.conf`
   (unmodified upstream mirror table).
4. Indexes ALL ~12,000 ports from `ports.tar.gz` into
   `config/versions/<ver>-catalog.tsv` so `make list-catalog` searches the full
   OpenBSD ports tree instantaneously while keeping git lean and fast.
5. Updates `tools/audit/vendor-baseline.tsv`.
"""
from __future__ import annotations

import argparse
import hashlib
import pathlib
import re
import subprocess
import sys
import tarfile
import urllib.request
from typing import Dict, List, Tuple

VAR_ASSIGN_RE = re.compile(r"^([A-Za-z0-9_.]+)\s*([+?]?=)\s*(.*)$")
VAR_REF_RE = re.compile(r"\$\{([A-Za-z0-9_.]+)(?::[^}]*)?\}|\$\(([A-Za-z0-9_.]+)\)|\$([A-Za-z0-9_])")


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fp:
        while True:
            chunk = fp.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def load_versions_manifest(manifest_path: pathlib.Path) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    headers: List[str] = []
    for raw in manifest_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        cols = raw.split("\t")
        if not headers:
            headers = cols
            continue
        row = {headers[i]: (cols[i] if i < len(cols) else "") for i in range(len(headers))}
        rows.append(row)
    return rows


def download_and_verify(url: str, dest: pathlib.Path, expected_sha256: str) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.is_file():
        actual = sha256_file(dest)
        if actual == expected_sha256:
            print(f"[sync-vendor] verified cached {dest} (sha256={actual[:16]}...)")
            return
        print(f"[sync-vendor] cached {dest} digest mismatch ({actual} != {expected_sha256}); re-downloading...")
        dest.unlink()

    part = dest.with_suffix(dest.suffix + ".part")
    print(f"[sync-vendor] downloading {url} -> {dest} ...")
    try:
        subprocess.run(
            ["curl", "-fL", "--retry", "3", "-o", str(part), url],
            check=True,
        )
    except FileNotFoundError:
        with urllib.request.urlopen(url, timeout=120) as resp, part.open("wb") as out:
            while True:
                chunk = resp.read(1024 * 512)
                if not chunk:
                    break
                out.write(chunk)

    actual = sha256_file(part)
    if actual != expected_sha256:
        part.unlink(missing_ok=True)
        raise SystemExit(
            f"[sync-vendor] SHA256 mismatch for {url}: expected {expected_sha256}, got {actual}"
        )
    part.replace(dest)
    print(f"[sync-vendor] verified {dest} (sha256={actual[:16]}...)")


def join_makefile_lines(text: str) -> Dict[str, str]:
    logical: List[str] = []
    cur = ""
    for raw in text.splitlines():
        s = raw.rstrip()
        # Strip unescaped comments conservatively
        if "#" in s:
            idx = s.find("#")
            if idx == 0 or s[idx - 1] != "\\":
                s = s[:idx].rstrip()
        if s.endswith("\\"):
            cur += (" " if cur else "") + s[:-1].strip()
        else:
            cur += (" " if cur else "") + s.strip()
            if cur:
                logical.append(cur)
            cur = ""
    if cur:
        logical.append(cur)

    env: Dict[str, str] = {}
    for ln in logical:
        m = VAR_ASSIGN_RE.match(ln)
        if not m:
            continue
        k, op, val = m.group(1), m.group(2), m.group(3).strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
            val = val[1:-1]
        if op == "+=" and k in env:
            env[k] = (env[k] + " " + val).strip()
        elif op == "?=" and k in env:
            continue
        else:
            env[k] = val
    return env


def expand_vars(val: str, env: Dict[str, str], depth: int = 0) -> str:
    if depth > 6 or "$" not in val:
        return val

    def repl(m: re.Match) -> str:
        name = m.group(1) or m.group(2) or m.group(3) or ""
        raw_v = env.get(name, "")
        return expand_vars(raw_v, env, depth + 1)

    return VAR_REF_RE.sub(repl, val)


def refresh_vendor_baseline(repo_root: pathlib.Path) -> int:
    vendor_versions = repo_root / "vendor/openbsd/versions"
    baseline_path = repo_root / "tools/audit/vendor-baseline.tsv"
    baseline_path.parent.mkdir(parents=True, exist_ok=True)

    rows: List[str] = ["# Immutable SHA256 baseline for vendor/openbsd/versions (DO NOT EDIT VENDOR FILES)", "version\trelpath\tsha256\tsize"]
    count = 0
    if vendor_versions.is_dir():
        for ver_dir in sorted(p for p in vendor_versions.iterdir() if p.is_dir()):
            ver = ver_dir.name
            for fpath in sorted(p for p in ver_dir.rglob("*") if p.is_file()):
                rel = fpath.relative_to(repo_root).as_posix()
                digest = sha256_file(fpath)
                sz = fpath.stat().st_size
                rows.append(f"{ver}\t{rel}\t{digest}\t{sz}")
                count += 1

    tmp = baseline_path.with_suffix(".tsv.tmp")
    tmp.write_text("\n".join(rows) + "\n", encoding="utf-8")
    tmp.replace(baseline_path)
    return count


def index_ports_tarball(
    tar_path: pathlib.Path,
    vendor_ports_dir: pathlib.Path,
    catalog_tsv_path: pathlib.Path,
) -> int:
    makefiles: Dict[str, str] = {}
    makefile_incs: Dict[str, str] = {}
    distinfos: Dict[str, List[str]] = {}
    netconf_bytes: bytes | None = None

    with tarfile.open(tar_path, "r:gz") as tf:
        for member in tf:
            if not member.isfile():
                continue
            name = member.name
            if "/CVS/" in name or not name.startswith("ports/"):
                continue
            rel = name[len("ports/") :]
            if rel == "infrastructure/db/network.conf":
                fp = tf.extractfile(member)
                if fp is not None:
                    netconf_bytes = fp.read()
                continue

            top = rel.split("/", 1)[0]
            if top in ("infrastructure", "INDEX"):
                continue

            base = rel.rsplit("/", 1)[-1] if "/" in rel else rel
            if base == "Makefile" and "/" in rel:
                portpath = rel[: -len("/Makefile")]
                fp = tf.extractfile(member)
                if fp is not None:
                    makefiles[portpath] = fp.read().decode("utf-8", "replace")
            elif base == "Makefile.inc" and "/" in rel:
                parent = rel[: -len("/Makefile.inc")]
                fp = tf.extractfile(member)
                if fp is not None:
                    makefile_incs[parent] = fp.read().decode("utf-8", "replace")
            elif base == "distinfo" and "/" in rel:
                portpath = rel[: -len("/distinfo")]
                fp = tf.extractfile(member)
                if fp is not None:
                    txt = fp.read().decode("utf-8", "replace")
                    dfiles: List[str] = []
                    for ln in txt.splitlines():
                        if ln.startswith("SHA256 (") and ") =" in ln:
                            fn = ln[len("SHA256 (") : ln.index(") =")].strip()
                            dfiles.append(fn)
                    distinfos[portpath] = dfiles

    if netconf_bytes is not None:
        out_nc = vendor_ports_dir / "infrastructure/db/network.conf"
        out_nc.parent.mkdir(parents=True, exist_ok=True)
        out_nc.write_bytes(netconf_bytes)

    # Filter out pure category/group Makefiles that only list SUBDIR += ...
    catalog_rows: List[str] = [
        "# Complete OpenBSD release ports catalog indexed from official SHA256-verified ports.tar.gz",
        "portpath\tpkgname\tcategories\tcomment\thomepage\tdistfiles",
    ]
    leaf_count = 0
    for portpath in sorted(makefiles.keys()):
        raw_mk = makefiles[portpath]
        env: Dict[str, str] = {}
        parts = portpath.split("/")
        for i in range(1, len(parts)):
            anc = "/".join(parts[:i])
            if anc in makefile_incs:
                env.update(join_makefile_lines(makefile_incs[anc]))
        env.update(join_makefile_lines(raw_mk))

        if "SUBDIR" in env and "DISTNAME" not in env and "PKGNAME" not in env and portpath not in distinfos:
            continue

        distname = expand_vars(env.get("DISTNAME", ""), env).strip()
        pkgname = expand_vars(env.get("PKGNAME", distname or parts[-1]), env).strip()
        categories = expand_vars(env.get("CATEGORIES", parts[0]), env).strip()
        comment = expand_vars(env.get("COMMENT", env.get("COMMENT-main", "")), env).replace("\t", " ").strip()
        homepage = expand_vars(env.get("HOMEPAGE", ""), env).replace("\t", " ").strip()
        dfiles_str = ",".join(distinfos.get(portpath, []))
        catalog_rows.append(f"{portpath}\t{pkgname}\t{categories}\t{comment}\t{homepage}\t{dfiles_str}")
        leaf_count += 1

    catalog_tsv_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_cat = catalog_tsv_path.with_suffix(".tsv.tmp")
    tmp_cat.write_text("\n".join(catalog_rows) + "\n", encoding="utf-8")
    tmp_cat.replace(catalog_tsv_path)
    return leaf_count


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--version", default="all", help="OpenBSD version to sync (default: all)")
    args = ap.parse_args()

    repo_root = pathlib.Path(__file__).resolve().parents[2]
    manifest = load_versions_manifest(repo_root / "config/versions/index.tsv")
    selected = [r for r in manifest if args.version == "all" or r["version"] == args.version]
    if not selected:
        raise SystemExit(f"unknown version '{args.version}'")

    for row in selected:
        ver = row["version"]
        tar_path = repo_root / ".cache/openbsd" / ver / "ports.tar.gz"
        download_and_verify(row["ports_url"], tar_path, row["ports_sha256"])
        vendor_ports_dir = repo_root / row["vendor_dir"]
        catalog_tsv_path = repo_root / row["catalog_tsv"]
        print(f"[sync-vendor] indexing OpenBSD {ver} ports catalog from {tar_path.name} ...")
        leaf_count = index_ports_tarball(tar_path, vendor_ports_dir, catalog_tsv_path)
        print(f"[sync-vendor] OpenBSD {ver}: indexed {leaf_count} ports -> {row['catalog_tsv']}")

    baseline_count = refresh_vendor_baseline(repo_root)
    print(f"[sync-vendor] refreshed vendor-baseline.tsv ({baseline_count} tracked vendor files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
