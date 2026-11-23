#!/usr/bin/env python3
"""
install_pure_python.py -- Deterministic offline pure-Python package installer
for OpenBSD WASM64 ports (`stage/usr/local/lib/python3.<minor>/site-packages`).

Zero network access and zero host pip/build-backend dependencies. Preserves
package data files, generates PEP 427/376 `.dist-info` metadata (`METADATA`,
`WHEEL`, `INSTALLER`, `entry_points.txt`) so `importlib.metadata.version()` and
`entry_points()` work identically to standard wheel installations, and strips
any `__pycache__` / `.pyc` artifacts.
"""
from __future__ import annotations

import argparse
import email.parser
import os
import pathlib
import re
import shutil
import stat
import sys
import tomllib

PY_VER_BY_OPENBSD = {
    "7.8": "3.12",
    "7.9": "3.13",
    "8.0": "3.14",
}


def normalize_dist_info_prefix(name: str) -> str:
    return re.sub(r"[-_.]+", "_", name).strip("_").lower()


def copy_clean_tree(src: pathlib.Path, dst: pathlib.Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    dst.mkdir(parents=True, exist_ok=True)
    for item in sorted(src.iterdir()):
        if item.name == "__pycache__" or item.name.endswith((".pyc", ".pyo", ".egg-info")):
            continue
        out = dst / item.name
        if item.is_dir():
            copy_clean_tree(item, out)
        elif item.is_file():
            shutil.copy2(item, out)
            out.chmod(0o644)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--package", action="append", default=[], help="Relative package dir or .py module in WRKSRC")
    ap.add_argument("--script", action="append", default=[], help="Console script spec name=module:func")
    ap.add_argument("--extra-site-dir", default="", help="Optional directory of extra modules/packages to copy into site-packages")
    args = ap.parse_args()

    obsd_ver = os.environ["OPENBSD_VERSION"]
    py_ver = PY_VER_BY_OPENBSD[obsd_ver]
    wrksrc = pathlib.Path(os.environ["WRKSRC"])
    stage_dir = pathlib.Path(os.environ["STAGE_DIR"])

    site_dir = stage_dir / f"usr/local/lib/python{py_ver}/site-packages"
    site_dir.mkdir(parents=True, exist_ok=True)

    pkg_info_path = wrksrc / "PKG-INFO"
    dist_name = ""
    dist_version = ""
    pkg_info_text = ""
    if pkg_info_path.is_file():
        pkg_info_text = pkg_info_path.read_text(encoding="utf-8", errors="replace")
        msg = email.parser.Parser().parsestr(pkg_info_text)
        dist_name = (msg.get("Name") or "").strip()
        dist_version = (msg.get("Version") or "").strip()

    pyproj = {}
    pyproj_path = wrksrc / "pyproject.toml"
    if pyproj_path.is_file():
        pyproj = tomllib.loads(pyproj_path.read_text(encoding="utf-8"))
        proj = pyproj.get("project", {})
        if not dist_name:
            dist_name = proj.get("name", "")
        if not dist_version:
            dist_version = proj.get("version", "")

    if not dist_name or not dist_version:
        raise SystemExit(f"install_pure_python: could not determine Name/Version in {wrksrc}")

    for rel in args.package:
        src_p = wrksrc / rel
        if not src_p.exists():
            raise SystemExit(f"install_pure_python: missing package source {src_p}")
        if src_p.is_dir():
            copy_clean_tree(src_p, site_dir / src_p.name)
        else:
            dst_f = site_dir / src_p.name
            shutil.copy2(src_p, dst_f)
            dst_f.chmod(0o644)

    if args.extra_site_dir:
        extra_root = pathlib.Path(args.extra_site_dir)
        if not extra_root.is_dir():
            raise SystemExit(f"install_pure_python: missing --extra-site-dir {extra_root}")
        for item in sorted(extra_root.iterdir()):
            if item.name.startswith(".") or item.name == "__pycache__" or item.name.endswith((".pyc", ".pyo")):
                continue
            if item.is_dir():
                copy_clean_tree(item, site_dir / item.name)
            elif item.is_file():
                dst_f = site_dir / item.name
                shutil.copy2(item, dst_f)
                dst_f.chmod(0o644)

    dist_info = site_dir / f"{normalize_dist_info_prefix(dist_name)}-{dist_version}.dist-info"
    if dist_info.exists():
        shutil.rmtree(dist_info)
    dist_info.mkdir(parents=True, exist_ok=True)

    if not pkg_info_text:
        pkg_info_text = f"Metadata-Version: 2.1\nName: {dist_name}\nVersion: {dist_version}\n"
    (dist_info / "METADATA").write_text(pkg_info_text, encoding="utf-8")
    (dist_info / "INSTALLER").write_text("obsd-ports\n", encoding="utf-8")
    (dist_info / "WHEEL").write_text(
        "Wheel-Version: 1.0\nGenerator: obsd-ports\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        encoding="utf-8",
    )

    proj = pyproj.get("project", {})
    ep_sections: dict[str, dict[str, str]] = {}
    if isinstance(proj.get("scripts"), dict) and proj["scripts"]:
        ep_sections["console_scripts"] = dict(proj["scripts"])
    if isinstance(proj.get("entry-points"), dict):
        for grp, mapping in proj["entry-points"].items():
            if isinstance(mapping, dict) and mapping:
                ep_sections[grp] = dict(mapping)

    if ep_sections:
        ep_lines: list[str] = []
        for grp, mapping in sorted(ep_sections.items()):
            ep_lines.append(f"[{grp}]")
            for k, v in sorted(mapping.items()):
                ep_lines.append(f"{k} = {v}")
            ep_lines.append("")
        (dist_info / "entry_points.txt").write_text("\n".join(ep_lines), encoding="utf-8")

    bin_dir = stage_dir / "usr/local/bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    for spec in args.script:
        if "=" not in spec or ":" not in spec:
            raise SystemExit(f"install_pure_python: invalid --script '{spec}', expected name=mod:func")
        name, target = spec.split("=", 1)
        mod_name, attr_path = target.split(":", 1)
        script_path = bin_dir / name.strip()
        script_text = (
            "#!/usr/local/bin/python3\n"
            "import os\n"
            "import sys\n"
            "if sys.pycache_prefix is None and not sys.flags.dont_write_bytecode:\n"
            "    sys.pycache_prefix = f'/tmp/.pycache-{os.getuid()}'\n"
            f"from {mod_name.strip()} import {attr_path.strip().split('.')[0]} as _entry\n"
        )
        parts = attr_path.strip().split(".")
        call_expr = "_entry" + "".join(f".{p}" for p in parts[1:])
        script_text += (
            "if __name__ == '__main__':\n"
            "    if sys.argv[0].endswith('-script.pyw'):\n"
            "        sys.argv[0] = sys.argv[0][:-11]\n"
            "    elif sys.argv[0].endswith('.exe'):\n"
            "        sys.argv[0] = sys.argv[0][:-4]\n"
            f"    sys.exit({call_expr}())\n"
        )
        script_path.write_text(script_text, encoding="utf-8")
        script_path.chmod(0o755)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
