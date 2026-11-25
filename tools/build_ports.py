#!/usr/bin/env python3
"""
build_ports.py -- Multi-axis OpenBSD Port Builder & Catalog Driver for `obsd-ports`.

Supports both `ports/**` (backed by immutable `vendor/openbsd/versions/<ver>/ports/`)
and first-class `extra/**` (self-contained OpenBSD-style ports absent from official
OpenBSD `7.8`/`7.9`/`8.0` release trees, including `MODULES = devel/cargo` via
`sdk/bin/obsd-cargo`), parameterized across the 3D matrix
`(OPENBSD_VERSION x COMPAT_BACKEND x COMPAT_PAL)`.
"""
from __future__ import annotations

import sys

if sys.version_info < (3, 11):  # tomllib (PEP 680) is stdlib only from 3.11 on
    sys.stderr.write(
        "build_ports: Python >= 3.11 is required (tomllib); %s is Python %d.%d.\n"
        "build_ports: run `make ... PYTHON=/path/to/python3.11+` (e.g. PYTHON=/opt/homebrew/bin/python3.13).\n"
        % ((sys.executable or "python3"), sys.version_info[0], sys.version_info[1])
    )
    raise SystemExit(2)

import argparse
import base64
import binascii
import bz2
import concurrent.futures
import fcntl
import gzip
import hashlib
import json
import lzma
import os
import pathlib
import platform
import re
import shlex
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
import threading
import time
import tomllib
import zipfile
import zlib
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools/config"))
import obsd_versions  # noqa: E402  (release axis from config/versions/index.tsv)
import obsd_env  # noqa: E402  (EMSDK_PYTHON pinning)

DISTINFO_SHA256_RE = re.compile(r"^SHA256\s*\((.+)\)\s*=\s*(\S+)\s*$")
DISTINFO_SIZE_RE = re.compile(r"^SIZE\s*\((.+)\)\s*=\s*(\d+)\s*$")
VAR_ASSIGN_RE = re.compile(r"^([A-Za-z0-9_.+-]+?)\s*([+?:!]?=)\s*(.*)$")
BRACED_VAR_RE = re.compile(r"\$\{([^{}]+)\}")
SIMPLE_PAREN_OR_CHAR_VAR_RE = re.compile(r"\$\(([A-Za-z0-9_.+-]+)\)|\$([A-Za-z0-9_])")
INCLUDE_QUOTED_RE = re.compile(r'^\.include\s+"([^"]+)"\s*$')
CARGO_SEMVER_STEM_RE = re.compile(r"^([A-Za-z0-9_-]+?)-(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._+-]+)?)$")

OVERRIDE_TABLE_KEYS = ("versions", "backends", "pals", "targets", "matrix")

DIST_TUPLE_SITES: Dict[str, Tuple[str, str]] = {
    "github": ("https://github.com", "{acct}/{proj}/archive/{ref}/"),
    "gitlab": ("https://gitlab.com", "{acct}/{proj}/-/archive/{ref}/"),
    "codeberg": ("https://codeberg.org", "{acct}/{proj}/archive/{ref}/"),
    "fdo": ("https://gitlab.freedesktop.org", "{acct}/{proj}/-/archive/{ref}/"),
    "kde": ("https://invent.kde.org", "{acct}/{proj}/-/archive/{ref}/"),
    "gnome": ("https://gitlab.gnome.org", "{acct}/{proj}/-/archive/{ref}/"),
    "srht": ("https://git.sr.ht", "~{acct}/{proj}/archive/{ref}/"),
}


def die(msg: str, code: int = 1) -> "NoReturn":
    sys.stderr.write(f"build_ports: {msg}\n")
    raise SystemExit(code)


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fp:
        while True:
            chunk = fp.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def decode_openbsd_sha256(digest_str: str) -> str:
    """Decode OpenBSD base64 SHA256 (or 64-char hex SHA256) to lowercase 64-char hex."""
    s = digest_str.strip()
    if len(s) == 64 and all(c in "0123456789abcdefABCDEF" for c in s):
        return s.lower()
    try:
        raw = base64.b64decode(s, validate=True)
    except binascii.Error as exc:
        raise ValueError(f"invalid SHA256 digest '{s}': {exc}") from exc
    if len(raw) != 32:
        raise ValueError(f"decoded SHA256 digest '{s}' has {len(raw)} bytes (expected 32)")
    return raw.hex()


def parse_distinfo(distinfo_path: pathlib.Path) -> List[Dict[str, Any]]:
    if not distinfo_path.is_file():
        die(f"missing distinfo: {distinfo_path}")
    digests: Dict[str, str] = {}
    sizes: Dict[str, int] = {}
    order: List[str] = []
    for raw in distinfo_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m_sha = DISTINFO_SHA256_RE.match(line)
        if m_sha:
            fname, raw_hash = m_sha.group(1).strip(), m_sha.group(2).strip()
            digests[fname] = decode_openbsd_sha256(raw_hash)
            if fname not in order:
                order.append(fname)
            continue
        m_sz = DISTINFO_SIZE_RE.match(line)
        if m_sz:
            fname, sz_s = m_sz.group(1).strip(), m_sz.group(2).strip()
            sizes[fname] = int(sz_s)
    entries = []
    for fn in order:
        entries.append(
            {
                "filename": fn,
                "sha256": digests[fn],
                "size": sizes.get(fn),
            }
        )
    return entries


def _read_logical_makefile_lines(p: pathlib.Path, seen_files: Set[pathlib.Path]) -> List[str]:
    rp = p.resolve()
    if rp in seen_files or not p.is_file():
        return []
    seen_files.add(rp)

    logical: List[str] = []
    cur = ""
    for raw in p.read_text(encoding="utf-8", errors="replace").splitlines():
        s = raw.rstrip()
        if "#" in s:
            idx = s.find("#")
            if idx == 0 or s[idx - 1] != "\\":
                s = s[:idx].rstrip()
        if s.endswith("\\"):
            cur += (" " if cur else "") + s[:-1].strip()
        else:
            cur += (" " if cur else "") + s.strip()
            if cur:
                m_inc = INCLUDE_QUOTED_RE.match(cur)
                if m_inc:
                    inc_rel = m_inc.group(1).strip()
                    inc_path = (p.parent / inc_rel).resolve() if not os.path.isabs(inc_rel) else pathlib.Path(inc_rel)
                    if inc_path.is_file():
                        logical.extend(_read_logical_makefile_lines(inc_path, seen_files))
                        cur = ""
                        continue
                logical.append(cur)
            cur = ""
    if cur:
        logical.append(cur)
    return logical


def parse_openbsd_makefile_vars(paths: Sequence[pathlib.Path]) -> Dict[str, str]:
    env: Dict[str, str] = {
        "LOCALBASE": "/usr/local",
        "PREFIX": "/usr/local",
        "TRUEPREFIX": "/usr/local",
        "SYSCONFDIR": "/etc",
    }
    seen_files: Set[pathlib.Path] = set()
    for p in paths:
        if not p.is_file():
            continue
        logical = _read_logical_makefile_lines(p, seen_files)

        def _unroll_for_loops(lines: Sequence[str], cur_env: Dict[str, str]) -> List[str]:
            out_lines: List[str] = []
            idx = 0
            while idx < len(lines):
                ln = lines[idx]
                m_for = re.match(r"^\.for\s+([A-Za-z0-9_]+)\s+in\s+(.*)$", ln)
                if not m_for:
                    out_lines.append(ln)
                    idx += 1
                    continue
                loop_var = m_for.group(1)
                items = expand_openbsd_expr(m_for.group(2), cur_env).split()
                depth = 1
                end_idx = idx + 1
                while end_idx < len(lines) and depth > 0:
                    if re.match(r"^\.for\b", lines[end_idx]):
                        depth += 1
                    elif re.match(r"^\.endfor\b", lines[end_idx]):
                        depth -= 1
                        if depth == 0:
                            break
                    end_idx += 1
                body = lines[idx + 1 : end_idx]
                var_pat = re.compile(
                    rf"\$\{{{re.escape(loop_var)}\}}|\$\({re.escape(loop_var)}\)|\$(?={re.escape(loop_var)}(?![A-Za-z0-9_])){re.escape(loop_var)}"
                )
                for item in items:
                    sub_body = [var_pat.sub(lambda _m, v=item: v, b) for b in body]
                    out_lines.extend(_unroll_for_loops(sub_body, cur_env))
                idx = end_idx + 1
            return out_lines

        for ln in _unroll_for_loops(logical, env):
            if ln.startswith("."):
                continue
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

            if k == "SHARED_LIBS":
                toks = env[k].split()
                for idx in range(0, len(toks) - 1, 2):
                    if not toks[idx].startswith("#"):
                        env[f"LIB{toks[idx]}_VERSION"] = toks[idx + 1]

    # Synthesize default DISTNAME from GH_* or DIST_TUPLE when omitted (matching bsd.port.mk / dist-tuple.port.mk)
    if "DISTNAME" not in env:
        if "GH_PROJECT" in env and ("GH_TAGNAME" in env or "GH_COMMIT" in env):
            proj = expand_openbsd_expr(env.get("GH_PROJECT", ""), env).strip()
            tag = expand_openbsd_expr(env.get("GH_TAGNAME", ""), env).strip()
            if proj and tag:
                ver_part = tag[1:] if (len(tag) > 1 and tag[0] in ("v", "V") and tag[1].isdigit()) else tag
                env["DISTNAME"] = f"{proj}-{ver_part}"
        elif "DIST_TUPLE" in env:
            dt = expand_openbsd_expr(env["DIST_TUPLE"], env).split()
            if len(dt) >= 5:
                _tmpl, _acct, proj, ref, _sub = dt[0], dt[1], dt[2], dt[3], dt[4]
                ver_part = ref[1:] if (len(ref) > 1 and ref[0] in ("v", "V") and ref[1].isdigit()) else ref
                env["DISTNAME"] = f"{proj}-{ver_part}"
    return env


def _apply_bmake_modifiers(val: str, mods_str: str) -> str:
    if mods_str.startswith("="):
        sub = mods_str[1:]
        return " ".join(t + sub for t in val.split())

    pos = 0
    n = len(mods_str)
    cur = val
    while pos < n:
        ch = mods_str[pos]
        if ch in ("R", "L") and (pos + 1 == n or mods_str[pos + 1] == ":"):
            if ch == "R":
                if " " in cur:
                    cur = " ".join(t.rsplit(".", 1)[0] if "." in t else t for t in cur.split())
                else:
                    cur = cur.rsplit(".", 1)[0] if "." in cur else cur
            else:
                cur = cur.lower()
            pos += 2 if (pos + 1 < n and mods_str[pos + 1] == ":") else 1
            continue

        if ch in ("S", "C") and pos + 1 < n:
            delim = mods_str[pos + 1]
            p_idx = pos + 2

            def _read_part(start: int) -> Tuple[str, int]:
                buf: List[str] = []
                k = start
                while k < n:
                    if mods_str[k] == "\\" and k + 1 < n and mods_str[k + 1] == delim:
                        buf.append(delim)
                        k += 2
                        continue
                    if mods_str[k] == delim:
                        return "".join(buf), k + 1
                    buf.append(mods_str[k])
                    k += 1
                return "".join(buf), k

            pat_raw, after_pat = _read_part(p_idx)
            rep_raw, after_rep = _read_part(after_pat)
            flags = ""
            k = after_rep
            while k < n and mods_str[k] != ":":
                flags += mods_str[k]
                k += 1
            pos = k + 1 if (k < n and mods_str[k] == ":") else k

            cnt = 0 if "g" in flags else 1
            if ch == "S":
                anc_s = pat_raw.startswith("^")
                anc_e = pat_raw.endswith("$")
                core = pat_raw[1 if anc_s else 0 : len(pat_raw) - (1 if anc_e and len(pat_raw) > (1 if anc_s else 0) else 0)]
                rx = ("^" if anc_s else "") + re.escape(core) + ("$" if anc_e else "")
                words = [cur] if "W" in flags else cur.split()
                new_words = [
                    re.sub(rx, lambda m, r=rep_raw: r.replace("&", m.group(0)), w, count=cnt)
                    for w in words
                ]
                cur = new_words[0] if "W" in flags else (" ".join(new_words) if cur.strip() else cur)
            else:
                def _crepl(m: re.Match, r: str = rep_raw) -> str:
                    out_c: List[str] = []
                    j = 0
                    while j < len(r):
                        if r[j] == "&":
                            out_c.append(m.group(0))
                            j += 1
                        elif r[j] == "\\" and j + 1 < len(r) and r[j + 1].isdigit():
                            grp = int(r[j + 1])
                            out_c.append(m.group(grp) if grp <= (m.lastindex or 0) and m.group(grp) is not None else "")
                            j += 2
                        else:
                            out_c.append(r[j])
                            j += 1
                    return "".join(out_c)

                words = [cur] if "W" in flags else cur.split()
                new_words = [re.sub(pat_raw, _crepl, w, count=cnt) for w in words]
                cur = new_words[0] if "W" in flags else (" ".join(new_words) if cur.strip() else cur)
            continue

        nxt = mods_str.find(":", pos)
        pos = nxt + 1 if nxt != -1 else n
    return cur


def expand_openbsd_expr(expr: str, env: Dict[str, str], depth: int = 0) -> str:
    if depth > 8 or "$" not in expr:
        return expr

    out = SIMPLE_PAREN_OR_CHAR_VAR_RE.sub(
        lambda m: expand_openbsd_expr(env.get(m.group(1) or m.group(2) or "", ""), env, depth + 1),
        expr,
    )
    for _ in range(8):
        if "${" not in out:
            break

        def _repl_braced(m: re.Match) -> str:
            body = m.group(1)
            if ":" in body:
                name, mods = body.split(":", 1)
                base_val = expand_openbsd_expr(env.get(name, ""), env, depth + 1)
                return _apply_bmake_modifiers(base_val, mods)
            return expand_openbsd_expr(env.get(body, ""), env, depth + 1)

        nxt = BRACED_VAR_RE.sub(_repl_braced, out)
        if nxt == out:
            break
        out = nxt
    return out


def get_port_makefile_paths(
    vendor_ports_dir: pathlib.Path,
    vendor_port: str,
    port_dir: Optional[pathlib.Path] = None,
    section: str = "ports",
    include_network_conf: bool = True,
) -> List[pathlib.Path]:
    mk_paths: List[pathlib.Path] = []
    if include_network_conf:
        net_conf = vendor_ports_dir / "infrastructure/db/network.conf"
        if net_conf.is_file():
            mk_paths.append(net_conf)

    if section == "extra":
        if port_dir is not None:
            mk_paths.append(port_dir / "Makefile")
            # If crates.inc exists and was not already pulled via `.include "crates.inc"`, parse_openbsd_makefile_vars
            # deduplicates via `seen_files`, so appending `crates.inc` is safely idempotent!
            if (port_dir / "crates.inc").is_file():
                mk_paths.append(port_dir / "crates.inc")
        return mk_paths

    parts = vendor_port.split("/")
    for i in range(1, len(parts)):
        anc = "/".join(parts[:i])
        mk_paths.append(vendor_ports_dir / anc / "Makefile.inc")
    mk_paths.append(vendor_ports_dir / vendor_port / "Makefile")
    if (vendor_ports_dir / vendor_port / "crates.inc").is_file():
        mk_paths.append(vendor_ports_dir / vendor_port / "crates.inc")
    return mk_paths


def parse_modcargo_crates_map(env: Dict[str, str]) -> Dict[str, Tuple[str, str]]:
    """Map `cargo/<crate>-<ver>.tar.gz` -> `(<crate>, <ver>)` from `MODCARGO_CRATES`."""
    raw = expand_openbsd_expr(env.get("MODCARGO_CRATES", ""), env)
    toks = raw.split()
    subdir = expand_openbsd_expr(env.get("MODCARGO_DIST_SUBDIR", "cargo"), env).strip().strip("/")
    prefix = f"{subdir}/" if subdir else ""
    out: Dict[str, Tuple[str, str]] = {}
    for i in range(0, len(toks) - 1, 2):
        cname, cver = toks[i], toks[i + 1]
        out[f"{prefix}{cname}-{cver}.tar.gz"] = (cname, cver)
    return out


def parse_dist_tuples(env: Dict[str, str]) -> List[Dict[str, str]]:
    if "DIST_TUPLE" not in env:
        return []
    toks = expand_openbsd_expr(env["DIST_TUPLE"], env).split()
    tuples: List[Dict[str, str]] = []
    for idx in range(0, len(toks) - 4, 5):
        tmpl, acct, proj, ref, targetdir = toks[idx : idx + 5]
        ver_part = ref[1:] if (len(ref) > 1 and ref[0] in ("v", "V") and ref[1].isdigit()) else ref
        tuples.append(
            {
                "template": tmpl,
                "account": acct,
                "project": proj,
                "ref": ref,
                "ver_part": ver_part,
                "targetdir": targetdir,
            }
        )
    return tuples


def resolve_cargo_crate_pair(distfile_name: str, cargo_map: Dict[str, Tuple[str, str]]) -> Optional[Tuple[str, str]]:
    if distfile_name in cargo_map:
        return cargo_map[distfile_name]
    if distfile_name.startswith("cargo/") and distfile_name.endswith(".tar.gz"):
        stem = distfile_name[len("cargo/") : -len(".tar.gz")]
        m = CARGO_SEMVER_STEM_RE.match(stem)
        if m:
            return m.group(1), m.group(2)
    return None


def resolve_distfile_urls(
    vendor_ports_dir: pathlib.Path,
    vendor_port: str,
    distfile_name: str,
    extra_sites: Sequence[str],
    port_dir: Optional[pathlib.Path] = None,
    section: str = "ports",
) -> List[str]:
    mk_paths = get_port_makefile_paths(
        vendor_ports_dir,
        vendor_port,
        port_dir=port_dir,
        section=section,
        include_network_conf=True,
    )
    env = parse_openbsd_makefile_vars(mk_paths)
    cargo_map = parse_modcargo_crates_map(env)

    # Fast-path Cargo `.crate` tarballs: resolve directly to static.crates.io + crates.io API + OpenBSD mirrors
    cargo_pair = resolve_cargo_crate_pair(distfile_name, cargo_map)
    if cargo_pair is not None:
        cname, cver = cargo_pair
        return [
            f"https://static.crates.io/crates/{cname}/{cname}-{cver}.crate",
            f"https://crates.io/api/v1/crates/{cname}/{cver}/download",
            f"https://cdn.openbsd.org/pub/OpenBSD/distfiles/{distfile_name}",
            f"https://ftp.openbsd.org/pub/OpenBSD/distfiles/{distfile_name}",
        ]

    sites_raw = list(extra_sites)
    leaf = distfile_name.rsplit("/", 1)[-1]

    matched_subkeys: Set[str] = set()
    for df_key, df_val in env.items():
        subkey = ""
        if df_key.startswith("DISTFILES."):
            subkey = df_key[len("DISTFILES.") :]
        elif df_key.startswith("PATCHFILES."):
            subkey = df_key[len("PATCHFILES.") :]
        if not subkey:
            continue
        for tok in expand_openbsd_expr(df_val, env).split():
            tok_clean = re.sub(r"\{[^}]*\}", "", re.sub(r":[0-9]$", "", tok))
            if tok_clean == leaf or tok_clean == distfile_name:
                matched_subkeys.add(subkey)

    for subkey in sorted(matched_subkeys):
        sub_sites = env.get(f"SITES.{subkey}", "")
        if sub_sites:
            sites_raw.extend(expand_openbsd_expr(sub_sites, env).split())

    for mk_key, mk_val in env.items():
        if mk_key == "SITES" or mk_key.startswith("SITES."):
            expanded = expand_openbsd_expr(mk_val, env)
            sites_raw.extend(expanded.split())

    # Match specific DIST_TUPLE entries before generic GitHub archive URLs
    dt_entries = parse_dist_tuples(env)
    matched_dt = False
    for dt in dt_entries:
        tmpl, acct, proj, ref, ver_part = dt["template"], dt["account"], dt["project"], dt["ref"], dt["ver_part"]
        proj_tail = proj.rsplit("/", 1)[-1]
        cand_leaves = {
            f"{acct}-{proj_tail}-{ref}.tar.gz",
            f"{acct}-{proj.replace('/', '-')}-{ref}.tar.gz",
            f"{proj_tail}-{ver_part}.tar.gz",
            f"{proj_tail}-{ref}.tar.gz",
        }
        if leaf in cand_leaves and tmpl in DIST_TUPLE_SITES:
            host_base, path_tmpl = DIST_TUPLE_SITES[tmpl]
            sites_raw.append(f"{host_base}/{path_tmpl.format(acct=acct, proj=proj, ref=ref)}")
            if tmpl == "github":
                sites_raw.append(f"https://github.com/{acct}/{proj}/releases/download/{ref}/")
            matched_dt = True

    gh_acct = expand_openbsd_expr(env.get("GH_ACCOUNT", ""), env).strip()
    gh_proj = expand_openbsd_expr(env.get("GH_PROJECT", ""), env).strip()
    gh_tag = expand_openbsd_expr(env.get("GH_TAGNAME", ""), env).strip()
    gh_commit = expand_openbsd_expr(env.get("GH_COMMIT", ""), env).strip()
    if gh_acct and gh_proj and (gh_tag or gh_commit) and not matched_dt:
        ref = gh_commit or gh_tag
        sites_raw.append(f"https://github.com/{gh_acct}/{gh_proj}/archive/{ref}/")
        if gh_tag:
            sites_raw.append(f"https://github.com/{gh_acct}/{gh_proj}/releases/download/{gh_tag}/")

    if dt_entries and not matched_dt:
        for dt in dt_entries:
            tmpl, acct, proj, ref = dt["template"], dt["account"], dt["project"], dt["ref"]
            if tmpl in DIST_TUPLE_SITES:
                host_base, path_tmpl = DIST_TUPLE_SITES[tmpl]
                sites_raw.append(f"{host_base}/{path_tmpl.format(acct=acct, proj=proj, ref=ref)}")
                if tmpl == "github":
                    sites_raw.append(f"https://github.com/{acct}/{proj}/releases/download/{ref}/")

    if expand_openbsd_expr(env.get("MODPY_PI", ""), env).strip().lower() == "yes":
        distname_val = expand_openbsd_expr(env.get("DISTNAME", ""), env).strip()
        modpy_distv = expand_openbsd_expr(env.get("MODPY_DISTV", env.get("MODPY_EGG_VERSION", "")), env).strip()
        if modpy_distv and distname_val.endswith(f"-{modpy_distv}"):
            egg_name = distname_val[: -len(f"-{modpy_distv}")]
        elif "-" in distname_val:
            egg_name = distname_val.rsplit("-", 1)[0]
        else:
            egg_name = distname_val
        pi_dir = expand_openbsd_expr(env.get("MODPY_PI_DIR", ""), env).strip().strip("/")
        if not pi_dir and egg_name:
            pi_dir = f"{egg_name[0]}/{egg_name}"
        if pi_dir:
            pypi_bases = expand_openbsd_expr(
                env.get("SITE_PYPI", "https://files.pythonhosted.org/packages/source/"),
                env,
            ).split()
            for pb in pypi_bases:
                sites_raw.append(f"{pb.rstrip('/')}/{pi_dir}/")

    sites_raw.extend(
        [
            "https://cdn.openbsd.org/pub/OpenBSD/distfiles/",
            "https://ftp.openbsd.org/pub/OpenBSD/distfiles/",
            f"https://cdn.openbsd.org/pub/OpenBSD/distfiles/{distfile_name.split('/', 1)[0]}/"
            if "/" in distfile_name
            else "",
        ]
    )

    remote_leaves: List[str] = [leaf]
    for df_key, df_val in env.items():
        if df_key == "DISTFILES" or df_key.startswith("DISTFILES.") or df_key == "PATCHFILES" or df_key.startswith("PATCHFILES."):
            for tok in expand_openbsd_expr(df_val, env).split():
                tok_clean = re.sub(r":[0-9]$", "", tok)
                m_brace = re.match(r"^([^{}\s]+)\{([^}]+)\}(.*)$", tok_clean)
                if m_brace:
                    local_nm = m_brace.group(1) + m_brace.group(3)
                    remote_nm = m_brace.group(2) + m_brace.group(3)
                    if local_nm == leaf and remote_nm not in remote_leaves:
                        remote_leaves.append(remote_nm)

    urls: List[str] = []
    seen: Set[str] = set()
    for s in sites_raw:
        s = s.strip()
        if not s or not s.startswith(("https://", "http://")):
            continue
        if not s.endswith("/"):
            s += "/"
        if "/OpenBSD/distfiles/" in s and "/" in distfile_name:
            cands = [s + distfile_name, *[s + rl for rl in remote_leaves]]
        else:
            cands = [*[s + rl for rl in remote_leaves], *([s + distfile_name] if "/" in distfile_name else [])]
        for candidate in cands:
            if candidate not in seen:
                seen.add(candidate)
                urls.append(candidate)
    return urls


def _apply_override_layer(recipe: Dict[str, Any], layer: Any) -> None:
    if not isinstance(layer, dict):
        return
    for k, v in layer.items():
        if k == "env" and isinstance(v, dict):
            merged_env = dict(recipe.get("env") or {})
            merged_env.update(v)
            recipe["env"] = merged_env
        elif k.endswith("_append") and isinstance(v, list):
            base_k = k[: -len("_append")]
            cur_list = list(recipe.get(base_k) or [])
            cur_list.extend(v)
            recipe[base_k] = cur_list
        else:
            recipe[k] = v


def load_recipe(
    port_dir: pathlib.Path,
    openbsd_version: str,
    ports_root: Optional[pathlib.Path] = None,
    backend: str = "emulate",
    pal: str = "emscripten",
    section: str = "ports",
) -> Dict[str, Any]:
    toml_path = port_dir / "port.toml"
    json_path = port_dir / "port.json"
    if toml_path.is_file():
        raw = tomllib.loads(toml_path.read_text(encoding="utf-8"))
    elif json_path.is_file():
        raw = json.loads(json_path.read_text(encoding="utf-8"))
    else:
        die(f"missing port.toml or port.json in {port_dir}")

    base_ports_root = ports_root or (REPO_ROOT / ("extra" if section == "extra" else "ports"))
    rel_port = port_dir.relative_to(base_ports_root).as_posix()

    recipe = dict(raw)
    versions_tbl = recipe.pop("versions", {})
    backends_tbl = recipe.pop("backends", {})
    pals_tbl = recipe.pop("pals", {})
    targets_tbl = recipe.pop("targets", {})
    matrix_tbl = recipe.pop("matrix", {})

    # Deterministic 6-layer override resolution:
    #   1. base -> 2. [versions."<ver>"] -> 3. [backends."<backend>"] ->
    #   4. [pals."<pal>"] -> 5. [targets."<backend>/<pal>"] ->
    #   6. [matrix."<ver>/<backend>/<pal>"]
    if isinstance(versions_tbl, dict):
        _apply_override_layer(recipe, versions_tbl.get(openbsd_version))
    if isinstance(backends_tbl, dict):
        _apply_override_layer(recipe, backends_tbl.get(backend))
    if isinstance(pals_tbl, dict):
        _apply_override_layer(recipe, pals_tbl.get(pal))
    if isinstance(targets_tbl, dict):
        _apply_override_layer(recipe, targets_tbl.get(f"{backend}/{pal}"))
    if isinstance(matrix_tbl, dict):
        _apply_override_layer(recipe, matrix_tbl.get(f"{openbsd_version}/{backend}/{pal}"))

    # Strip any nested override tables if accidentally placed inside an override block
    for ov_k in OVERRIDE_TABLE_KEYS:
        recipe.pop(ov_k, None)

    recipe["port"] = recipe.get("port", rel_port)
    recipe["vendor_port"] = recipe.get("vendor_port", recipe["port"])
    recipe["port_dir"] = port_dir
    recipe["section"] = section

    for gate_k in (
        "only_versions",
        "only_for_versions",
        "not_for_versions",
        "only_for_backends",
        "not_for_backends",
        "only_for_pals",
        "not_for_pals",
        "only_for_targets",
        "not_for_targets",
    ):
        if gate_k in recipe and recipe[gate_k] is not None:
            recipe[gate_k] = [str(x).strip() for x in recipe[gate_k]]

    recipe.setdefault("depends", [])
    recipe.setdefault("build_style", "gnu")
    recipe.setdefault("separate_build", False)
    recipe.setdefault("use_gmake", True)
    recipe.setdefault("apply_vendor_patches", True)
    recipe.setdefault("skip_vendor_patches", [])
    recipe.setdefault("skip_distfiles", [])
    recipe.setdefault("patch_strip", 0)
    recipe.setdefault("applets", [])
    return recipe


def recipe_supports_lane(
    recipe: Dict[str, Any],
    openbsd_version: str,
    backend: str = "emulate",
    pal: str = "emscripten",
) -> Tuple[bool, str]:
    target_cell = f"{backend}/{pal}"

    only_vers = recipe.get("only_for_versions")
    if only_vers is None:
        only_vers = recipe.get("only_versions")
    if only_vers is not None and openbsd_version not in [str(v).strip() for v in only_vers]:
        return False, f"only_for_versions={only_vers} (current: {openbsd_version})"

    not_vers = recipe.get("not_for_versions")
    if not_vers is not None and openbsd_version in [str(v).strip() for v in not_vers]:
        return False, f"not_for_versions={not_vers} (current: {openbsd_version})"

    only_backends = recipe.get("only_for_backends")
    if only_backends is not None and backend not in [str(x).strip() for x in only_backends]:
        return False, f"only_for_backends={only_backends} (current: {backend})"

    not_backends = recipe.get("not_for_backends")
    if not_backends is not None and backend in [str(x).strip() for x in not_backends]:
        return False, f"not_for_backends={not_backends} (current: {backend})"

    only_pals = recipe.get("only_for_pals")
    if only_pals is not None and pal not in [str(x).strip() for x in only_pals]:
        return False, f"only_for_pals={only_pals} (current: {pal})"

    not_pals = recipe.get("not_for_pals")
    if not_pals is not None and pal in [str(x).strip() for x in not_pals]:
        return False, f"not_for_pals={not_pals} (current: {pal})"

    only_targets = recipe.get("only_for_targets")
    if only_targets is not None and target_cell not in [str(x).strip() for x in only_targets]:
        return False, f"only_for_targets={only_targets} (current: {target_cell})"

    not_targets = recipe.get("not_for_targets")
    if not_targets is not None and target_cell in [str(x).strip() for x in not_targets]:
        return False, f"not_for_targets={not_targets} (current: {target_cell})"

    return True, ""


def recipe_supports_version(recipe: Dict[str, Any], openbsd_version: str) -> bool:
    ok, _ = recipe_supports_lane(recipe, openbsd_version)
    return ok


def discover_recipes(
    openbsd_version: str,
    target_ports: Optional[Sequence[str]] = None,
    ports_root: Optional[pathlib.Path] = None,
    backend: str = "emulate",
    pal: str = "emscripten",
    section: str = "all",
    extra_root: Optional[pathlib.Path] = None,
    include_cross_section_deps: bool = True,
) -> List[Dict[str, Any]]:
    if section not in ("all", "ports", "extra"):
        die(f"invalid --section '{section}' (expected: all, ports, extra)")

    custom_single_root = ports_root is not None and extra_root is None
    p_root = ports_root or (REPO_ROOT / "ports")
    e_root = extra_root or (REPO_ROOT / "extra")

    raw_map: Dict[str, Dict[str, Any]] = {}
    all_map: Dict[str, Dict[str, Any]] = {}
    gate_reasons: Dict[str, str] = {}

    def _scan_section_root(root_dir: pathlib.Path, sec_name: str) -> None:
        if not root_dir.is_dir():
            return
        for p in sorted(root_dir.rglob("port.toml")) + sorted(root_dir.rglob("port.json")):
            port_dir = p.parent
            rel = port_dir.relative_to(root_dir).as_posix()
            if rel in raw_map:
                prev_sec = raw_map[rel].get("section", sec_name)
                if prev_sec != sec_name:
                    die(f"duplicate port '{rel}' declared in both {prev_sec}/ and {sec_name}/")
                continue
            rec = load_recipe(
                port_dir,
                openbsd_version,
                ports_root=root_dir,
                backend=backend,
                pal=pal,
                section=sec_name,
            )
            raw_map[rel] = rec
            ok, reason = recipe_supports_lane(rec, openbsd_version, backend=backend, pal=pal)
            if ok:
                all_map[rel] = rec
            else:
                gate_reasons[rel] = reason

    if custom_single_root:
        _scan_section_root(p_root, "ports" if section == "all" else section)
    else:
        _scan_section_root(p_root, "ports")
        _scan_section_root(e_root, "extra")

    if not raw_map:
        return []

    def _matches_section(rec: Dict[str, Any]) -> bool:
        return section == "all" or rec.get("section") == section

    if target_ports:
        wanted: Set[str] = set()

        def add_with_deps(name: str, required_by: Optional[str] = None) -> None:
            norm = name.strip().strip("/")
            explicit_sec: Optional[str] = None
            if norm.startswith("ports/"):
                explicit_sec = "ports"
                norm = norm[len("ports/") :]
            elif norm.startswith("extra/"):
                explicit_sec = "extra"
                norm = norm[len("extra/") :]

            if norm not in raw_map:
                die(
                    f"port recipe '{norm}' not found under ports/ or extra/ "
                    f"(available: {', '.join(sorted(raw_map)) or 'none'})"
                )
            rec_raw = raw_map[norm]
            if explicit_sec is not None and rec_raw.get("section") != explicit_sec:
                die(f"port '{norm}' lives under {rec_raw.get('section')}/, not {explicit_sec}/")
            if required_by is None and section != "all" and rec_raw.get("section") != section:
                die(
                    f"port '{norm}' belongs to section '{rec_raw.get('section')}', "
                    f"but --section '{section}' was requested"
                )
            if required_by is not None and section == "ports" and rec_raw.get("section") == "extra":
                die(f"ports/ recipe '{required_by}' cannot depend on extra/ recipe '{norm}'")

            if norm not in all_map:
                if required_by is not None:
                    die(f"port '{required_by}' depends on '{norm}', which is gated out: {gate_reasons.get(norm, '')}")
                return
            if norm in wanted:
                return
            wanted.add(norm)
            if include_cross_section_deps:
                for dep in all_map[norm].get("depends", []):
                    add_with_deps(dep, required_by=norm)

        for tp in target_ports:
            for item in tp.split(","):
                if item.strip():
                    add_with_deps(item)
    else:
        wanted = {k for k, r in all_map.items() if _matches_section(r)}

    ordered: List[Dict[str, Any]] = []
    visiting: Set[str] = set()
    visited: Set[str] = set()

    def visit(name: str, required_by: Optional[str] = None) -> None:
        if name in visited:
            return
        if name in visiting:
            die(f"cyclic port dependency involving '{name}'")
        visiting.add(name)
        rec = all_map.get(name)
        if rec is None:
            if name in raw_map:
                die(f"dependency port '{name}' is gated out: {gate_reasons.get(name, '')}")
            die(f"missing dependency port recipe '{name}' (searched ports/ and extra/)")
        if required_by is not None and raw_map[required_by].get("section") == "ports" and rec.get("section") == "extra":
            die(f"ports/ recipe '{required_by}' cannot depend on extra/ recipe '{name}'")
        for dep in rec.get("depends", []):
            if not include_cross_section_deps and dep in all_map and not _matches_section(all_map[dep]):
                continue
            visit(dep, required_by=name)
        visiting.remove(name)
        visited.add(name)
        ordered.append(rec)

    for name in sorted(wanted):
        visit(name)
    return ordered


def is_skipped_distfile(filename: str, skip_set: Set[str]) -> bool:
    if not skip_set:
        return False
    leaf = filename.rsplit("/", 1)[-1]
    return filename in skip_set or leaf in skip_set


def _download_and_verify_one_distfile(
    ent: Dict[str, Any],
    dest: pathlib.Path,
    urls: Sequence[str],
    openbsd_version: str,
    port_name: str,
) -> Tuple[pathlib.Path, Dict[str, Any]]:
    fn = ent["filename"]
    expected_sha = ent["sha256"]
    expected_sz = ent["size"]
    dest.parent.mkdir(parents=True, exist_ok=True)

    if dest.is_file():
        actual_sz = dest.stat().st_size
        if expected_sz is None or actual_sz == expected_sz:
            if sha256_file(dest) == expected_sha:
                return dest, ent

    lock_path = dest.parent / f".{dest.name}.lock"
    with lock_path.open("w") as lock_fp:
        fcntl.flock(lock_fp.fileno(), fcntl.LOCK_EX)
        if dest.is_file():
            actual_sz = dest.stat().st_size
            if (expected_sz is None or actual_sz == expected_sz) and sha256_file(dest) == expected_sha:
                return dest, ent
            dest.unlink(missing_ok=True)

        part = dest.parent / f".{dest.name}.{os.getpid()}.{threading.get_ident()}.part"
        last_err = "no candidate URLs"
        try:
            for url in urls:
                for attempt in range(3):
                    if attempt > 0:
                        time.sleep(0.5 * (2 ** (attempt - 1)))
                    if not fn.startswith("cargo/") or attempt > 0:
                        print(f"[fetch/{openbsd_version}] {port_name}: {url}")
                    part.unlink(missing_ok=True)
                    proc = subprocess.run(
                        [
                            "curl",
                            "-fL",
                            "--connect-timeout",
                            "15",
                            "--max-time",
                            "600",
                            "--retry",
                            "2",
                            "-sS",
                            "-o",
                            str(part),
                            url,
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    if proc.returncode != 0 or not part.is_file():
                        last_err = proc.stderr.strip() or f"curl exit {proc.returncode}"
                        # 404 (curl exit 22 with 404) moves straight to fallback URL; transient errors retry
                        if "404" in last_err:
                            break
                        continue
                    actual_sz = part.stat().st_size
                    if expected_sz is not None and actual_sz != expected_sz:
                        last_err = f"size mismatch from {url}: got {actual_sz}, expected {expected_sz}"
                        part.unlink(missing_ok=True)
                        break
                    actual_sha = sha256_file(part)
                    if actual_sha != expected_sha:
                        last_err = f"SHA256 mismatch from {url}: got {actual_sha}, expected {expected_sha}"
                        part.unlink(missing_ok=True)
                        break
                    part.replace(dest)
                    if not fn.startswith("cargo/"):
                        print(f"[fetch/{openbsd_version}] verified {fn} (sha256={actual_sha[:16]}..., {actual_sz} bytes)")
                    return dest, ent
        finally:
            part.unlink(missing_ok=True)

    die(f"failed to fetch & verify distfile '{fn}' for {port_name}: {last_err}")


def fetch_port_distfiles(
    recipe: Dict[str, Any],
    openbsd_version: str,
    repo_root: Optional[pathlib.Path] = None,
    jobs: int = 16,
) -> List[Tuple[pathlib.Path, Dict[str, Any]]]:
    root = repo_root or REPO_ROOT
    section = recipe.get("section", "ports")
    vendor_ports_dir = root / "vendor/openbsd/versions" / openbsd_version / "ports"
    vport = recipe["vendor_port"]
    port_dir: pathlib.Path = recipe["port_dir"]

    if section == "extra":
        meta_dir = port_dir
        if not (meta_dir / "distinfo").is_file():
            die(f"extra port '{recipe['port']}' is missing {meta_dir / 'distinfo'}")
    else:
        meta_dir = vendor_ports_dir / vport
        if not meta_dir.is_dir():
            die(
                f"port '{recipe['port']}' has no vendored OpenBSD {openbsd_version} subtree at {meta_dir}; "
                f"run `make import PORT={vport}` first"
            )

    entries = parse_distinfo(meta_dir / "distinfo")
    skip_set = {str(x) for x in recipe.get("skip_distfiles", [])}
    cache_dist = root / ".cache/distfiles"
    extra_sites = recipe.get("sites", [])

    active_entries = [ent for ent in entries if not is_skipped_distfile(ent["filename"], skip_set)]
    if not active_entries:
        return []

    # Fast check for already-verified local files, and parallel download for any missing/stale files
    to_fetch_indices: List[int] = []
    results: List[Optional[Tuple[pathlib.Path, Dict[str, Any]]]] = [None] * len(active_entries)

    for idx, ent in enumerate(active_entries):
        dest = cache_dist / ent["filename"]
        if dest.is_file():
            exp_sz = ent["size"]
            if exp_sz is None or dest.stat().st_size == exp_sz:
                if sha256_file(dest) == ent["sha256"]:
                    results[idx] = (dest, ent)
                    continue
        to_fetch_indices.append(idx)

    if to_fetch_indices:
        if len(to_fetch_indices) > 1:
            print(
                f"[fetch/{openbsd_version}] {recipe['port']}: downloading {len(to_fetch_indices)} distfile(s) "
                f"with {min(max(jobs, 4), 24, len(to_fetch_indices))} parallel worker(s)..."
            )
        url_cache: Dict[int, List[str]] = {}
        for idx in to_fetch_indices:
            ent = active_entries[idx]
            url_cache[idx] = resolve_distfile_urls(
                vendor_ports_dir,
                vport,
                ent["filename"],
                extra_sites,
                port_dir=port_dir,
                section=section,
            )

        workers = min(max(jobs, 4), 24, len(to_fetch_indices))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            fut_map = {
                pool.submit(
                    _download_and_verify_one_distfile,
                    active_entries[idx],
                    cache_dist / active_entries[idx]["filename"],
                    url_cache[idx],
                    openbsd_version,
                    recipe["port"],
                ): idx
                for idx in to_fetch_indices
            }
            for fut in concurrent.futures.as_completed(fut_map):
                idx = fut_map[fut]
                results[idx] = fut.result()

        cargo_fetched = sum(1 for idx in to_fetch_indices if active_entries[idx]["filename"].startswith("cargo/"))
        if cargo_fetched:
            print(f"[fetch/{openbsd_version}] {recipe['port']}: verified {cargo_fetched} cargo crate archive(s)")

    return [r for r in results if r is not None]


def decompress_lzip_stream(src_path: pathlib.Path, dst_fp: Any) -> None:
    """Pure-Python LZIP v1 (.lz) multi-member decompressor with CRC32 & size verification."""
    buf = b""
    members_decoded = 0
    with src_path.open("rb") as src_fp:
        while True:
            while len(buf) < 6:
                chunk = src_fp.read(262144)
                if not chunk:
                    break
                buf += chunk

            if not buf:
                if members_decoded == 0:
                    die(f"cannot extract {src_path.name}: empty LZIP archive")
                break

            if not buf.startswith(b"LZIP"):
                if members_decoded > 0:
                    rest = src_fp.read()
                    if all(b == 0 for b in buf) and all(b == 0 for b in rest):
                        break
                die(f"cannot extract {src_path.name}: invalid LZIP header magic")

            if len(buf) < 6:
                die(f"cannot extract {src_path.name}: truncated 6-byte LZIP header")

            ver = buf[4]
            if ver != 1:
                die(f"cannot extract {src_path.name}: unsupported LZIP version {ver}")

            ds = buf[5]
            base = 1 << (ds & 0x1F)
            dict_size = base - (base >> 4) * ((ds >> 5) & 0x07)
            if dict_size < 4096 or dict_size > (512 << 20):
                die(f"cannot extract {src_path.name}: invalid LZIP dictionary size {dict_size}")

            buf = buf[6:]
            member_bytes = 6
            crc = 0
            data_size = 0
            dec = lzma.LZMADecompressor(
                format=lzma.FORMAT_RAW,
                filters=[{"id": lzma.FILTER_LZMA1, "dict_size": dict_size, "lc": 3, "lp": 0, "pb": 2}],
            )

            while not dec.eof:
                if not buf:
                    chunk = src_fp.read(262144)
                    if not chunk:
                        die(f"cannot extract {src_path.name}: unexpected EOF in LZIP compressed stream")
                    buf = chunk
                in_len = len(buf)
                out = dec.decompress(buf)
                unused = dec.unused_data
                member_bytes += in_len - len(unused)
                buf = unused
                if out:
                    crc = zlib.crc32(out, crc)
                    data_size += len(out)
                    dst_fp.write(out)

            while len(buf) < 20:
                chunk = src_fp.read(262144)
                if not chunk:
                    break
                buf += chunk
            if len(buf) < 20:
                die(f"cannot extract {src_path.name}: truncated 20-byte LZIP member trailer")

            exp_crc, exp_data_size, exp_member_size = struct.unpack("<IQQ", buf[:20])
            buf = buf[20:]
            member_bytes += 20

            actual_crc = crc & 0xFFFFFFFF
            if actual_crc != exp_crc:
                die(f"cannot extract {src_path.name}: LZIP CRC32 mismatch (0x{actual_crc:08x} != 0x{exp_crc:08x})")
            if data_size != exp_data_size:
                die(f"cannot extract {src_path.name}: LZIP data size mismatch ({data_size} != {exp_data_size})")
            if member_bytes != exp_member_size:
                die(f"cannot extract {src_path.name}: LZIP member size mismatch ({member_bytes} != {exp_member_size})")
            members_decoded += 1


def extract_archive(archive_path: pathlib.Path, extract_root: pathlib.Path) -> None:
    name = archive_path.name.lower()
    if name.endswith(".zip"):
        with zipfile.ZipFile(archive_path, "r") as zf:
            for info in zf.infolist():
                out_p = extract_root / info.filename
                if info.is_dir():
                    out_p.mkdir(parents=True, exist_ok=True)
                    continue
                out_p.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info, "r") as src, out_p.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
                unix_mode = (info.external_attr >> 16) & 0o7777
                if unix_mode:
                    out_p.chmod(unix_mode)
        return

    if name.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar", ".crate")):
        with tarfile.open(archive_path, "r:*") as tf:
            tf.extractall(path=extract_root, filter="data")
        return

    if name.endswith(".tar.zst"):
        subprocess.run(["tar", "--zstd", "-xf", str(archive_path), "-C", str(extract_root)], check=True)
        return

    if name.endswith(".tar.lz"):
        with tempfile.TemporaryFile(dir=str(extract_root.parent)) as tmp_tar:
            decompress_lzip_stream(archive_path, tmp_tar)
            tmp_tar.seek(0)
            with tarfile.open(fileobj=tmp_tar, mode="r:") as tf:
                tf.extractall(path=extract_root, filter="data")
        return

    die(f"unsupported archive format: {archive_path.name}")


def detect_wrksrc(extract_root: pathlib.Path, wrksrc_subdir: str) -> pathlib.Path:
    if wrksrc_subdir:
        cand = extract_root / wrksrc_subdir
        if not cand.is_dir():
            die(f"configured wrksrc_subdir '{wrksrc_subdir}' does not exist under {extract_root}")
        return cand
    children = [p for p in extract_root.iterdir() if not p.name.startswith(".")]
    dirs = [p for p in children if p.is_dir()]
    files = [p for p in children if p.is_file()]
    if len(dirs) == 1 and not files:
        return dirs[0]
    return extract_root


def parse_vendor_patchfiles(vendor_env: Dict[str, str], recipe: Dict[str, Any]) -> Tuple[Dict[str, int], int]:
    """Return ({patch_filename_or_basename: strip_level}, default_dist_strip) for OpenBSD PATCHFILES."""
    raw_strip = expand_openbsd_expr(vendor_env.get("PATCH_DIST_STRIP", "-p0"), vendor_env).strip()
    m_st = re.search(r"-p(\d+)", raw_strip)
    default_strip = int(recipe.get("patch_dist_strip", int(m_st.group(1)) if m_st else 0))

    patch_map: Dict[str, int] = {}
    dist_subdir = expand_openbsd_expr(vendor_env.get("DIST_SUBDIR", ""), vendor_env).strip().strip("/")

    explicit_list = recipe.get("patchfiles")
    tokens: List[str] = []
    if explicit_list is not None:
        tokens.extend(str(x) for x in explicit_list)
    else:
        for mk_key, mk_val in vendor_env.items():
            if mk_key == "PATCHFILES" or mk_key.startswith("PATCHFILES."):
                tokens.extend(expand_openbsd_expr(mk_val, vendor_env).split())

    for tok in tokens:
        p_strip = default_strip
        m_col = re.match(r"^(.+):(\d)$", tok)
        if m_col:
            tok = m_col.group(1)
            p_strip = int(m_col.group(2))
        m_brace = re.match(r"^([^{}\s]+)\{([^}]+)\}(.*)$", tok)
        if m_brace:
            tok = m_brace.group(1) + m_brace.group(3)
        patch_map[tok] = p_strip
        if dist_subdir and "/" not in tok:
            patch_map[f"{dist_subdir}/{tok}"] = p_strip
    return patch_map, default_strip


def read_patch_payload(patch_path: pathlib.Path) -> bytes:
    low = patch_path.name.lower()
    raw = patch_path.read_bytes()
    if low.endswith(".gz"):
        return gzip.decompress(raw)
    if low.endswith(".bz2"):
        return bz2.decompress(raw)
    if low.endswith(".xz"):
        return lzma.decompress(raw)
    return raw


def apply_patch_bytes(payload: bytes, wrksrc: pathlib.Path, strip_level: int, label: str) -> None:
    print(f"  [patch] applying {label} (-p{strip_level})")
    proc = subprocess.run(
        [
            "patch",
            f"-p{strip_level}",
            "-f",
            "-N",
            "-s",
            "--no-backup-if-mismatch",
            "-d",
            str(wrksrc),
        ],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        die(
            f"patch failed ({label}) in {wrksrc}:\n"
            f"{proc.stdout.decode('utf-8', 'replace')}\n{proc.stderr.decode('utf-8', 'replace')}"
        )


def apply_patch_dir(patch_dir: pathlib.Path, wrksrc: pathlib.Path, strip_level: int, skip_set: Set[str], label: str) -> None:
    if not patch_dir.is_dir():
        return
    patch_files = sorted(p for p in patch_dir.iterdir() if p.is_file() and p.name.startswith("patch-"))
    for pf in patch_files:
        if pf.name in skip_set:
            print(f"  [patch] skipping {label}/{pf.name} (per recipe)")
            continue
        print(f"  [patch] applying {label}/{pf.name}")
        with pf.open("rb") as stdin_fp:
            proc = subprocess.run(
                [
                    "patch",
                    f"-p{strip_level}",
                    "-f",
                    "-N",
                    "-s",
                    "--no-backup-if-mismatch",
                    "-d",
                    str(wrksrc),
                ],
                stdin=stdin_fp,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        if proc.returncode != 0:
            die(
                f"patch failed ({label}/{pf.name}) in {wrksrc}:\n"
                f"{proc.stdout.decode('utf-8', 'replace')}\n{proc.stderr.decode('utf-8', 'replace')}"
            )


def get_port_pkgname(
    vendor_ports_dir: pathlib.Path,
    vendor_port: str,
    port_dir: Optional[pathlib.Path] = None,
    section: str = "ports",
) -> str:
    mk_paths = get_port_makefile_paths(
        vendor_ports_dir,
        vendor_port,
        port_dir=port_dir,
        section=section,
        include_network_conf=False,
    )
    env = parse_openbsd_makefile_vars(mk_paths)
    parts = vendor_port.split("/")
    distname = expand_openbsd_expr(env.get("DISTNAME", ""), env).strip()
    raw_pkg = env.get("PKGNAME", env.get("PKGNAME-main", distname or parts[-1]))
    pkgname = expand_openbsd_expr(raw_pkg, env).strip()
    if not pkgname or "$" in pkgname or "/" in pkgname:
        pkgname = distname if (distname and "$" not in distname and "/" not in distname) else parts[-1]
    return pkgname


def get_port_comment_and_descr(
    vendor_ports_dir: pathlib.Path,
    vendor_port: str,
    port_dir: pathlib.Path,
    section: str,
) -> Tuple[str, str]:
    meta_dir = port_dir if section == "extra" else (vendor_ports_dir / vendor_port)
    mk_paths = get_port_makefile_paths(
        vendor_ports_dir,
        vendor_port,
        port_dir=port_dir,
        section=section,
        include_network_conf=False,
    )
    env = parse_openbsd_makefile_vars(mk_paths)
    comment = expand_openbsd_expr(env.get("COMMENT", env.get("COMMENT-main", "")), env).strip()
    descr_path = meta_dir / "pkg/DESCR"
    if not descr_path.is_file():
        descr_path = meta_dir / "pkg/DESCR-main"
    descr = descr_path.read_text(encoding="utf-8", errors="replace").strip() if descr_path.is_file() else ""
    return comment, descr


def parse_plist_bins(meta_dir: pathlib.Path) -> List[str]:
    plist = meta_dir / "pkg/PLIST"
    if not plist.is_file():
        return []
    bins: List[str] = []
    for raw in plist.read_text(encoding="utf-8", errors="replace").splitlines():
        s = raw.strip()
        if s.startswith("@bin bin/"):
            b = s[len("@bin bin/") :].strip()
            if b and "/" not in b:
                bins.append(b)
        elif s.startswith("bin/"):
            b = s[len("bin/") :].strip()
            if b and "/" not in b:
                bins.append(b)
    return bins


_TOOLCHAIN_DIGESTS: Dict[Tuple[str, str, str, str, str], str] = {}


def resolve_lane_sdk(pal: str, backend: str, explicit_sdk: str = "") -> str:
    if pal != "darwin":
        return ""
    sdk = (explicit_sdk or os.environ.get("COMPAT_SDK", "")).strip()
    if not sdk:
        sdk = "macosx" if backend == "translate" else "iphonesimulator"
    if backend == "translate" and sdk != "macosx":
        die(f"Darwin translate supports only COMPAT_SDK=macosx (got '{sdk}')", 2)
    if backend == "emulate" and sdk not in ("iphonesimulator", "iphoneos", "macosx"):
        die(f"Darwin emulate supports COMPAT_SDK=iphonesimulator|iphoneos|macosx (got '{sdk}')", 2)
    return sdk


def compute_lane_dir(
    openbsd_version: str,
    backend: str,
    pal: str,
    sdk: str = "",
    build_root_arg: str = "",
) -> pathlib.Path:
    raw = build_root_arg.strip() or os.environ.get("BUILD_ROOT", "").strip()
    base = pathlib.Path(raw).resolve() if raw else (REPO_ROOT / "build")
    leaf = f"darwin-{sdk}" if pal == "darwin" and sdk else pal
    return base / "openbsd" / openbsd_version / backend / leaf


def _digest_tree(h: "hashlib._Hash", root: pathlib.Path, label: str) -> None:
    h.update(f"[{label}]".encode())
    if not root.exists():
        h.update(b"<missing>")
        return
    for f in sorted(root.rglob("*")):
        if "__pycache__" in f.parts:
            continue
        rel = f.relative_to(root).as_posix().encode()
        if f.is_symlink():
            h.update(rel + b"->" + os.readlink(f).encode())
        elif f.is_file():
            h.update(rel + b"=" + sha256_file(f).encode())


def _semantic_identity_bytes(ident_path: pathlib.Path) -> bytes:
    """Hash only compiler/header-defining identity keys so transient host PATHs in
    `.object-build-identity` never invalidate clean port stamps."""
    if not ident_path.is_file():
        return b"<missing>"
    keep = [
        ln
        for ln in ident_path.read_text(encoding="utf-8", errors="replace").splitlines()
        if ln.startswith(("V=", "BOUNDARY_SDK=", "INCLUDE_ROOT=", "BOUNDARY_ARCH_FLAGS=", "CONSUMER_CFLAGS="))
    ]
    return "\n".join(sorted(keep)).encode("utf-8")


def toolchain_digest(
    obsd_root: pathlib.Path,
    openbsd_version: str,
    backend: str,
    pal: str,
    sdk: str = "",
    style: str = "",
) -> str:
    """Content digest of everything a port compiles against besides its own
    sources: sdk/ (wrappers, flags, autoconf/cmake or rust), the libobsdcompat
    `include-root-<v>` headers, and the lane identity/toolchain. Computed once per run."""
    eff_style = "cargo" if style == "cargo" else ""
    key = (str(obsd_root), openbsd_version, backend, pal, sdk, eff_style)
    if key not in _TOOLCHAIN_DIGESTS:
        h = hashlib.sha256()
        if eff_style == "cargo":
            _digest_tree(h, REPO_ROOT / "sdk/rust", "sdk-rust")
            for rel_f in (
                "sdk/bin/obsd-cargo",
                "sdk/bin/obsd-rust-ld",
                "sdk/bin/obsd-install",
                "sdk/lib/obsd-python.sh",
            ):
                fp = REPO_ROOT / rel_f
                h.update(rel_f.encode() + b"=" + (sha256_file(fp).encode() if fp.is_file() else b"<missing>"))
        else:
            _digest_tree(h, REPO_ROOT / "sdk", "sdk")
        if pal == "emscripten":
            wasm_dir = obsd_root / f"build/wasm-{openbsd_version}"
            _digest_tree(h, wasm_dir / f"include-root-{openbsd_version}", "include-root")
            ver_txt = obsd_root / "deps/emsdk/upstream/emscripten/emscripten-version.txt"
            h.update(b"[emsdk]" + (ver_txt.read_bytes() if ver_txt.is_file() else b"<missing>"))
        elif pal == "darwin":
            if backend == "translate":
                vec = obsd_root / f"build/openbsd/{openbsd_version}/translate/gen/guest-configure/tool-probe-vector.tsv"
                ident = obsd_root / f"build/openbsd-boundary/obj-{openbsd_version}-kern-gate/.object-build-identity"
                h.update(b"[vec]" + (vec.read_bytes() if vec.is_file() else b"<missing>"))
                h.update(b"[ident]" + _semantic_identity_bytes(ident))
            else:
                ident = obsd_root / f"build/openbsd-boundary/obj-{openbsd_version}-kern-gate-emulate-{sdk}/.object-build-identity"
                h.update(b"[ident]" + _semantic_identity_bytes(ident))
                _digest_tree(h, obsd_root / "tools/build/llvm-guest-bank", "llvm-guest-bank")
        _TOOLCHAIN_DIGESTS[key] = h.hexdigest()
    return _TOOLCHAIN_DIGESTS[key]


def host_python_shim_dir() -> pathlib.Path:
    """Directory whose `python3` is this (>=3.11) interpreter, so recipe hooks
    (`python3 -I "$PORT_DIR/..."`) never fall back to an older system python3."""
    d = REPO_ROOT / ".cache/sdk/host-python"
    d.mkdir(parents=True, exist_ok=True)
    link = d / "python3"
    target = pathlib.Path(sys.executable)
    if not (link.is_symlink() and os.readlink(link) == str(target)):
        tmp = d / f".python3.{os.getpid()}"
        if tmp.is_symlink() or tmp.exists():
            tmp.unlink()
        tmp.symlink_to(target)
        os.replace(tmp, link)
    return d


def make_sdk_env(
    openbsd_version: str,
    backend: str,
    pal: str,
    sdk: str,
    obsd_root: pathlib.Path,
    stage_dir: pathlib.Path,
    wrksrc: pathlib.Path,
    wrkbuild: pathlib.Path,
    port_dir: pathlib.Path,
    vendor_port_dir: pathlib.Path,
    vendor_env: Dict[str, str],
    recipe: Dict[str, Any],
    jobs: int,
) -> Dict[str, str]:
    sdk_bin = REPO_ROOT / "sdk/bin"
    guest_arch = "arm64" if pal == "darwin" else "wasm64"
    env = dict(os.environ)
    env["OBSD_PORTS_ROOT"] = str(REPO_ROOT)
    env["LIBOBSDCOMPAT_ROOT"] = str(obsd_root)
    env["OPENBSD_VERSION"] = openbsd_version
    env["COMPAT_BACKEND"] = backend
    env["COMPAT_PAL"] = pal
    if sdk:
        env["COMPAT_SDK"] = sdk
    else:
        env.pop("COMPAT_SDK", None)
    env["OBSD_GUEST_ARCH"] = guest_arch
    env["OBSD_STAGE_DIR"] = str(stage_dir)
    env["OBSD_PYTHON"] = sys.executable  # sdk/bin/obsd-* reuse this >=3.11 interpreter

    cc = str(sdk_bin / "obsd-cc")
    cxx = str(sdk_bin / "obsd-c++")
    ar = str(sdk_bin / "obsd-ar")
    ranlib = str(sdk_bin / "obsd-ranlib")
    ld = str(sdk_bin / "obsd-ld")
    nm = str(sdk_bin / "obsd-nm")
    strip_bin = str(sdk_bin / "obsd-strip")
    pkg_cfg = str(sdk_bin / "obsd-pkg-config")
    install_bin = str(sdk_bin / "obsd-install")
    cargo_bin = str(sdk_bin / "obsd-cargo")
    config_site = str(
        REPO_ROOT / ("sdk/autoconf/config.site.darwin" if pal == "darwin" else "sdk/autoconf/config.site")
    )
    cmake_tc = str(
        REPO_ROOT / ("sdk/cmake/openbsd-darwin.cmake" if pal == "darwin" else "sdk/cmake/openbsd-wasm64.cmake")
    )

    env["PATH"] = f"{sdk_bin}:{host_python_shim_dir()}:{env.get('PATH', '/usr/bin:/bin')}"
    env["CC"] = cc
    env["CXX"] = cxx
    env["CPP"] = f"{cc} -E"
    env["AR"] = ar
    env["RANLIB"] = ranlib
    env["LD"] = ld
    env["NM"] = nm
    env["STRIP"] = strip_bin
    env["PKG_CONFIG"] = pkg_cfg
    env["CARGO"] = cargo_bin
    env["INSTALL"] = install_bin
    env["INSTALL_PROGRAM"] = f"{install_bin} -c -m 0755"
    env["INSTALL_SCRIPT"] = f"{install_bin} -c -m 0755"
    env["INSTALL_DATA"] = f"{install_bin} -c -m 0644"
    env["INSTALL_MAN"] = f"{install_bin} -c -m 0444"
    env["INSTALL_DATA_DIR"] = f"{install_bin} -d -m 0755"
    env["CONFIG_SITE"] = config_site
    env["CMAKE_TOOLCHAIN_FILE"] = cmake_tc

    host_cc = shutil.which("clang") or shutil.which("gcc") or shutil.which("cc") or "cc"
    env["CC_FOR_BUILD"] = host_cc
    env["BUILD_CC"] = host_cc
    env["HOSTCC"] = host_cc
    if not shutil.which("makeinfo"):
        env.setdefault("MAKEINFO", "true")

    base_cf = ["-O2", *recipe.get("cflags", [])]
    base_cxxf = ["-O2", *recipe.get("cxxflags", [])]
    base_cppf = [f"-I{stage_dir}/usr/local/include", *recipe.get("cppflags", [])]
    base_ldf = [f"-L{stage_dir}/usr/local/lib", *recipe.get("ldflags", [])]
    base_libs = list(recipe.get("libs", []))

    env["CFLAGS"] = " ".join(base_cf).strip()
    env["CXXFLAGS"] = " ".join(base_cxxf).strip()
    env["CPPFLAGS"] = " ".join(base_cppf).strip()
    env["LDFLAGS"] = " ".join(base_ldf).strip()
    if base_libs:
        env["LIBS"] = " ".join(base_libs)

    env["PREFIX"] = "/usr/local"
    env["LOCALBASE"] = "/usr/local"
    env["SYSCONFDIR"] = "/etc"
    env["DESTDIR"] = str(stage_dir)
    env["STAGE_DIR"] = str(stage_dir)
    env["WRKSRC"] = str(wrksrc)
    env["WRKBUILD"] = str(wrkbuild)
    env["PORT_DIR"] = str(port_dir)
    env["VENDOR_PORT_DIR"] = str(vendor_port_dir)
    env["JOBS"] = str(jobs)

    if recipe.get("skip_distfiles"):
        env["OBSD_SKIP_DISTFILES_JSON"] = json.dumps([str(x) for x in recipe["skip_distfiles"]])
    if recipe.get("cargo_patch_crates"):
        env["OBSD_CARGO_PATCH_CRATES_JSON"] = json.dumps(recipe["cargo_patch_crates"])

    rustflags_list = list(recipe.get("cargo_rustflags", []))
    mk_rf = expand_openbsd_expr(vendor_env.get("MODCARGO_RUSTFLAGS", ""), vendor_env).strip()
    if mk_rf:
        rustflags_list.append(mk_rf)
    if rustflags_list:
        env["MODCARGO_RUSTFLAGS"] = " ".join(str(x) for x in rustflags_list).strip()

    for k, v in vendor_env.items():
        if k.startswith("LIB") and k.endswith("_VERSION"):
            env.setdefault(k, v)

    for k, v in recipe.get("env", {}).items():
        env[str(k)] = str(v).replace("${OBSD_GUEST_ARCH}", guest_arch)

    return env


def run_step(cmd: Sequence[str] | str, cwd: pathlib.Path, env: Dict[str, str], desc: str) -> None:
    if isinstance(cmd, str):
        print(f"  [{desc}] sh -c {cmd}")
        proc = subprocess.run(["bash", "-euo", "pipefail", "-c", cmd], cwd=str(cwd), env=env)
    else:
        print(f"  [{desc}] {' '.join(shlex.quote(str(x)) for x in cmd)}")
        proc = subprocess.run([str(x) for x in cmd], cwd=str(cwd), env=env)
    if proc.returncode != 0:
        die(f"{desc} failed with exit code {proc.returncode} in {cwd}")


def snapshot_tree(root: pathlib.Path) -> Dict[str, Tuple[int, int]]:
    snap: Dict[str, Tuple[int, int]] = {}
    if not root.exists():
        return snap
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dp = pathlib.Path(dirpath)
        for nm in list(dirnames) + list(filenames):
            fp = dp / nm
            rel = fp.relative_to(root).as_posix()
            st = fp.lstat()
            snap[rel] = (st.st_mtime_ns, st.st_size)
    return snap


def _extract_cargo_crates_parallel(
    cargo_archives: Sequence[Tuple[str, pathlib.Path, str]],
    vendor_dir: pathlib.Path,
    jobs: int,
) -> None:
    if not cargo_archives:
        return
    vendor_dir.mkdir(parents=True, exist_ok=True)

    def _one(item: Tuple[str, pathlib.Path, str]) -> None:
        stem, ar_path, sha_hex = item
        dest = vendor_dir / stem
        tmp_p = vendor_dir / f".tmp-{stem}.{os.getpid()}"
        shutil.rmtree(tmp_p, ignore_errors=True)
        tmp_p.mkdir(parents=True, exist_ok=True)
        try:
            with tarfile.open(ar_path, "r:*") as tf:
                tf.extractall(path=tmp_p, filter="data")
            subs = [p for p in tmp_p.iterdir() if p.is_dir()]
            src_d = subs[0] if len(subs) == 1 else tmp_p
            shutil.rmtree(dest, ignore_errors=True)
            shutil.move(str(src_d), str(dest))
            (dest / ".cargo-checksum.json").write_text(
                json.dumps({"files": {}, "package": sha_hex}) + "\n",
                encoding="utf-8",
            )
        finally:
            shutil.rmtree(tmp_p, ignore_errors=True)

    workers = min(max(jobs, 4), 24, len(cargo_archives))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(_one, cargo_archives))


def build_single_port(
    recipe: Dict[str, Any],
    openbsd_version: str,
    backend: str,
    pal: str,
    obsd_root: pathlib.Path,
    lane_dir: pathlib.Path,
    jobs: int,
    sdk: str = "",
    force: bool = False,
    repo_root: Optional[pathlib.Path] = None,
) -> Dict[str, Any]:
    root = repo_root or REPO_ROOT
    section = recipe.get("section", "ports")
    port_name = recipe["port"]
    vport = recipe["vendor_port"]
    port_dir: pathlib.Path = recipe["port_dir"]
    vendor_ports_dir = root / "vendor/openbsd/versions" / openbsd_version / "ports"
    vendor_port_dir = port_dir if section == "extra" else (vendor_ports_dir / vport)
    pkgname = recipe.get("pkgname") or get_port_pkgname(
        vendor_ports_dir,
        vport,
        port_dir=port_dir,
        section=section,
    )
    lane_tag = f"{backend}/darwin-{sdk}" if pal == "darwin" and sdk else f"{backend}/{pal}"

    stage_dir = lane_dir / "stage"
    stage_dir.mkdir(parents=True, exist_ok=True)
    for sub in ("bin", "sbin", "lib", "lib/pkgconfig", "include", "share", "man", "man/man1"):
        (stage_dir / "usr/local" / sub).mkdir(parents=True, exist_ok=True)

    stamps_dir = lane_dir / ".stamps"
    stamps_dir.mkdir(parents=True, exist_ok=True)
    stamp_slug = port_name.replace("/", "__")
    stamp_file = stamps_dir / f"{stamp_slug}.json"

    fetched = fetch_port_distfiles(recipe, openbsd_version, repo_root=root, jobs=jobs)

    # Compute deterministic recipe + metadata + distfile build signature.
    # For `section == "ports"`, omit `"section"` from `sig_recipe` so all pre-existing
    # `ports/*` stamps maintain 100% identical signatures without unnecessary rebuilds.
    sig_h = hashlib.sha256()
    excluded_sig_keys = {"port_dir"} | ({"section"} if section == "ports" else set())
    sig_recipe = {k: v for k, v in recipe.items() if k not in excluded_sig_keys}
    sig_h.update(json.dumps(sig_recipe, default=str, sort_keys=True).encode("utf-8"))
    if section != "extra" and vendor_port_dir.is_dir():
        for vf in sorted(vendor_port_dir.rglob("*")):
            if vf.is_file():
                sig_h.update(vf.relative_to(vendor_port_dir).as_posix().encode())
                sig_h.update(sha256_file(vf).encode())
    for pf in sorted(port_dir.rglob("*")):
        if pf.is_file():
            sig_h.update(pf.relative_to(port_dir).as_posix().encode())
            sig_h.update(sha256_file(pf).encode())
    for _df_path, df_ent in fetched:
        sig_h.update(df_ent["sha256"].encode())
    # Header/SDK dependencies: a changed libobsdcompat include-root, SDK wrapper
    # or emsdk release must rebuild ports (no stale objects after a lib update).
    port_style = str(recipe.get("build_style", "gnu")).strip()
    sig_h.update(toolchain_digest(obsd_root, openbsd_version, backend, pal, sdk, style=port_style).encode())
    build_sig = sig_h.hexdigest()

    if not force and stamp_file.is_file():
        old = json.loads(stamp_file.read_text(encoding="utf-8"))
        if old.get("signature") == build_sig:
            all_present = all(
                (stage_dir / rel).exists() or (stage_dir / rel).is_symlink()
                for rel in old.get("installed_files", [])
            )
            if all_present:
                print(f"[build/{openbsd_version}] {port_name} ({pkgname}): up-to-date")
                return old

    print(f"==> [build/{openbsd_version}] building {port_name} ({pkgname}) [{section} | {lane_tag}]...")
    work_port_dir = lane_dir / "work" / port_name
    if work_port_dir.exists():
        shutil.rmtree(work_port_dir)
    src_extract_dir = work_port_dir / "src"
    src_extract_dir.mkdir(parents=True, exist_ok=True)

    mk_paths = get_port_makefile_paths(
        vendor_ports_dir,
        vport,
        port_dir=port_dir,
        section=section,
        include_network_conf=True,
    )
    vendor_env = parse_openbsd_makefile_vars(mk_paths)
    dist_patch_map, _default_dist_strip = parse_vendor_patchfiles(vendor_env, recipe)

    # Map DIST_TUPLE entries that specify a non-`.` target subdirectory (e.g. `modcargo-crates/cudaforge-0.1.6`)
    dt_target_map: Dict[str, str] = {}
    for dt in parse_dist_tuples(vendor_env):
        if dt["targetdir"] != ".":
            proj_tail = dt["project"].rsplit("/", 1)[-1]
            for cand_leaf in (
                f"{dt['account']}-{proj_tail}-{dt['ref']}.tar.gz",
                f"{dt['account']}-{dt['project'].replace('/', '-')}-{dt['ref']}.tar.gz",
                f"{proj_tail}-{dt['ver_part']}.tar.gz",
                f"{proj_tail}-{dt['ref']}.tar.gz",
            ):
                dt_target_map[cand_leaf] = dt["targetdir"]

    skip_dist_set = {str(x) for x in recipe.get("skip_distfiles", [])}
    extract_only = set(recipe.get("extract_only", []))
    dist_patches_to_apply: List[Tuple[pathlib.Path, str, int]] = []
    cargo_archives: List[Tuple[str, pathlib.Path, str]] = []
    deferred_dt_archives: List[Tuple[pathlib.Path, str]] = []

    for df_path, ent in fetched:
        fn = ent["filename"]
        if is_skipped_distfile(fn, skip_dist_set) or df_path.name in skip_dist_set:
            continue
        if fn in dist_patch_map or df_path.name in dist_patch_map:
            st_lvl = dist_patch_map.get(fn, dist_patch_map.get(df_path.name, 0))
            dist_patches_to_apply.append((df_path, fn, st_lvl))
            continue
        if fn.startswith("cargo/") and fn.endswith(".tar.gz"):
            stem = fn[len("cargo/") : -len(".tar.gz")]
            cargo_archives.append((stem, df_path, ent["sha256"]))
            continue
        if df_path.name in dt_target_map:
            deferred_dt_archives.append((df_path, dt_target_map[df_path.name]))
            continue
        if extract_only and df_path.name not in extract_only and fn not in extract_only:
            continue
        extract_archive(df_path, src_extract_dir)

    wrksrc = detect_wrksrc(src_extract_dir, recipe.get("wrksrc_subdir", ""))
    if recipe.get("separate_build", False):
        wrkbuild = work_port_dir / "build"
        wrkbuild.mkdir(parents=True, exist_ok=True)
    else:
        wrkbuild = wrksrc

    # Place any `DIST_TUPLE` targetdir != "." archives (matching OpenBSD `MODDIST-TUPLE_post-extract`)
    for dt_ar, target_rel in deferred_dt_archives:
        tmp_dt = work_port_dir / f".dt-{dt_ar.name}"
        tmp_dt.mkdir(parents=True, exist_ok=True)
        extract_archive(dt_ar, tmp_dt)
        extracted_sub = detect_wrksrc(tmp_dt, "")
        target_dest = (wrksrc / target_rel).resolve()
        if target_dest.exists():
            shutil.rmtree(target_dest)
        target_dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(extracted_sub), str(target_dest))
        shutil.rmtree(tmp_dt, ignore_errors=True)
        if (target_dest / "Cargo.toml").is_file():
            (target_dest / ".cargo-checksum.json").write_text('{"files":{},"package":null}\n', encoding="utf-8")

    # Extract `cargo/*.tar.gz` into `$WRKSRC/modcargo-crates/<crate>-<ver>` BEFORE patches run
    # (matching OpenBSD `MODCARGO_post-extract` -> `patch` ordering so `patches/patch-*` can patch crates too!)
    if cargo_archives:
        print(f"  [modcargo] extracting {len(cargo_archives)} crate(s) -> {wrksrc / 'modcargo-crates'}...")
        _extract_cargo_crates_parallel(cargo_archives, wrksrc / "modcargo-crates", jobs=jobs)

    for crlf_rel in recipe.get("fix_crlf_files", []):
        crlf_path = wrksrc / crlf_rel
        if crlf_path.is_file():
            crlf_path.write_bytes(crlf_path.read_bytes().replace(b"\r\n", b"\n"))

    skip_patches = set(recipe.get("skip_vendor_patches", []))
    if recipe.get("apply_dist_patches", True):
        for dp_path, dp_fn, dp_strip in dist_patches_to_apply:
            if dp_fn in skip_patches or dp_path.name in skip_patches:
                print(f"  [patch] skipping distpatch/{dp_fn} (per recipe)")
                continue
            apply_patch_bytes(read_patch_payload(dp_path), wrksrc, dp_strip, f"distpatch/{dp_fn}")

    pstrip = int(recipe.get("patch_strip", 0))
    local_pdir = recipe.get("local_patch_dir", "patches")
    if section == "extra":
        # For self-contained `extra/` ports, apply `extra/<port>/patches/patch-*` ONCE (respecting `skip_vendor_patches` / `skip_patches`).
        skip_local = skip_patches | set(recipe.get("skip_patches", []))
        apply_patch_dir(port_dir / local_pdir, wrksrc, pstrip, skip_local, f"extra/{port_name}/{local_pdir}")
    else:
        if recipe.get("apply_vendor_patches", True):
            apply_patch_dir(vendor_port_dir / "patches", wrksrc, pstrip, skip_patches, f"vendor/{vport}/patches")
        apply_patch_dir(port_dir / local_pdir, wrksrc, pstrip, set(recipe.get("skip_patches", [])), f"ports/{port_name}/{local_pdir}")

    env = make_sdk_env(
        openbsd_version=openbsd_version,
        backend=backend,
        pal=pal,
        sdk=sdk,
        obsd_root=obsd_root,
        stage_dir=stage_dir,
        wrksrc=wrksrc,
        wrkbuild=wrkbuild,
        port_dir=port_dir,
        vendor_port_dir=vendor_port_dir,
        vendor_env=vendor_env,
        recipe=recipe,
        jobs=jobs,
    )
    guest_arch = env["OBSD_GUEST_ARCH"]
    exp_args = lambda seq: [str(x).replace("${OBSD_GUEST_ARCH}", guest_arch) for x in seq]

    make_prog = (shutil.which("gmake") or "make") if recipe.get("use_gmake", True) else "make"
    before_snap = snapshot_tree(stage_dir)

    for hook in recipe.get("pre_configure", []):
        run_step(hook, wrksrc, env, f"{port_name}:pre-configure")

    style = recipe["build_style"]
    custom_script = port_dir / "build.sh"

    if style == "script" or (custom_script.is_file() and style == "custom"):
        if custom_script.is_file():
            run_step(["bash", "-euo", "pipefail", str(custom_script)], wrkbuild, env, f"{port_name}:build.sh")
        else:
            for cmd in recipe.get("build_cmd", []):
                run_step(cmd, wrkbuild, env, f"{port_name}:build")
    elif style == "cargo":
        obsd_cargo = str(REPO_ROOT / "sdk/bin/obsd-cargo")
        manifest_rel = recipe.get("cargo_manifest_path", "")
        if not manifest_rel:
            mk_ct = expand_openbsd_expr(vendor_env.get("MODCARGO_CARGOTOML", ""), vendor_env).strip()
            if mk_ct and not mk_ct.startswith("$") and mk_ct != "/Cargo.toml":
                manifest_rel = mk_ct.lstrip("/")
        manifest_path = (wrksrc / manifest_rel).resolve() if manifest_rel else (wrksrc / "Cargo.toml")
        env["OBSD_CARGO_MANIFEST_PATH"] = str(manifest_path)

        run_step([obsd_cargo, "prepare"], wrkbuild, env, f"{port_name}:cargo-configure")

        for hook in recipe.get("post_configure", []):
            run_step(hook, wrkbuild, env, f"{port_name}:post-configure")
        for hook in recipe.get("pre_build", []):
            run_step(hook, wrkbuild, env, f"{port_name}:pre-build")

        if recipe.get("build_cmd"):
            for bcmd in recipe["build_cmd"]:
                run_step(bcmd, wrkbuild, env, f"{port_name}:build")
        else:
            cargo_cmd: List[str] = [
                obsd_cargo,
                "build",
                "--release",
                "-j",
                str(jobs),
                "--manifest-path",
                str(manifest_path),
            ]
            for pkg_sel in recipe.get("cargo_packages", []):
                cargo_cmd.extend(["-p", str(pkg_sel)])
            for bin_sel in recipe.get("cargo_bins", []):
                cargo_cmd.extend(["--bin", str(bin_sel)])

            no_def = recipe.get("cargo_no_default_features")
            if no_def is None:
                mk_nd = expand_openbsd_expr(vendor_env.get("MODCARGO_NO_DEFAULT_FEATURES", ""), vendor_env).strip().lower()
                no_def = mk_nd == "yes"
            if no_def:
                cargo_cmd.append("--no-default-features")

            feats = recipe.get("cargo_features")
            if feats is None:
                mk_f = expand_openbsd_expr(vendor_env.get("MODCARGO_FEATURES", ""), vendor_env).strip()
                feats = mk_f.replace(",", " ").split() if mk_f else []
            elif isinstance(feats, str):
                feats = [f.strip() for f in feats.replace(",", " ").split() if f.strip()]
            if feats:
                cargo_cmd.extend(["--features", ",".join(str(f) for f in feats)])

            cargo_cmd.extend(str(x) for x in recipe.get("cargo_args", []))
            run_step(cargo_cmd, wrkbuild, env, f"{port_name}:cargo-build")

        if recipe.get("install_cmd"):
            for icmd in recipe["install_cmd"]:
                run_step(icmd, wrkbuild, env, f"{port_name}:install")
        else:
            # Resolve target release output directory via `obsd-cargo target-info`
            t_info = json.loads(
                subprocess.check_output(
                    [
                        obsd_cargo,
                        "target-info",
                        "--openbsd-version",
                        openbsd_version,
                        "--backend",
                        backend,
                        "--pal",
                        pal,
                        *(["--sdk", sdk] if sdk else []),
                    ],
                    text=True,
                )
            )
            rel_out_dir = wrkbuild / "target" / t_info["target_name"] / "release"
            bins_to_stage: List[str] = [str(b) for b in recipe.get("cargo_bins", [])]
            if not bins_to_stage:
                bins_to_stage = parse_plist_bins(vendor_port_dir)
            if not bins_to_stage:
                for app in recipe.get("applets", []):
                    bp = str(app.get("binary") or (app.get("paths") or [""])[0]).strip()
                    if bp.startswith("/usr/local/bin/"):
                        bins_to_stage.append(bp.rsplit("/", 1)[-1])
            bins_to_stage = list(dict.fromkeys(bins_to_stage))
            if not bins_to_stage:
                die(f"{port_name}: build_style='cargo' found no binaries to install (set cargo_bins, pkg/PLIST @bin, or [[applets]])")

            install_bin = str(REPO_ROOT / "sdk/bin/obsd-install")
            for bname in bins_to_stage:
                built_bin = rel_out_dir / bname
                if not built_bin.is_file():
                    die(f"{port_name}: expected compiled Cargo binary at {built_bin}")
                run_step(
                    [install_bin, "-c", "-m", "0755", str(built_bin), str(stage_dir / "usr/local/bin" / bname)],
                    wrkbuild,
                    env,
                    f"{port_name}:cargo-install:{bname}",
                )
    else:
        if style in ("gnu", "simple"):
            cfg_rel = recipe.get("configure_script", "./configure")
            cfg_bin = (wrksrc / cfg_rel).resolve() if not os.path.isabs(cfg_rel) else pathlib.Path(cfg_rel)
            raw_arch = (platform.machine() or "x86_64").lower()
            host_arch = {"arm64": "aarch64", "amd64": "x86_64"}.get(raw_arch, raw_arch)
            cfg_cmd: List[str] = ["sh", str(cfg_bin)]
            if recipe.get("configure_host", style == "gnu"):
                cfg_cmd.extend(
                    [
                        f"--host=aarch64-unknown-openbsd{openbsd_version}",
                        f"--build={host_arch}-unknown-linux-gnu",
                    ]
                )
            if recipe.get("configure_default_args", style == "gnu"):
                cfg_cmd.extend(
                    [
                        "--prefix=/usr/local",
                        "--sysconfdir=/etc",
                        "--mandir=/usr/local/man",
                        "--disable-shared",
                        "--enable-static",
                    ]
                )
            cfg_cmd.extend(exp_args(recipe.get("configure_args", [])))
            run_step(cfg_cmd, wrkbuild, env, f"{port_name}:configure")

        elif style == "cmake":
            cmake_cmd = [
                "cmake",
                "-S",
                str(wrksrc),
                "-B",
                str(wrkbuild),
                f"-DCMAKE_TOOLCHAIN_FILE={env['CMAKE_TOOLCHAIN_FILE']}",
                "-DCMAKE_BUILD_TYPE=Release",
                "-DCMAKE_INSTALL_PREFIX=/usr/local",
                "-DCMAKE_INSTALL_MANDIR=/usr/local/man",
                "-DBUILD_SHARED_LIBS=OFF",
                *exp_args(recipe.get("cmake_args", [])),
            ]
            run_step(cmake_cmd, wrkbuild, env, f"{port_name}:cmake-configure")

        elif style == "make":
            pass
        else:
            die(f"{port_name}: unsupported build_style '{style}'")

        for hook in recipe.get("post_configure", []):
            run_step(hook, wrkbuild, env, f"{port_name}:post-configure")

        for hook in recipe.get("pre_build", []):
            run_step(hook, wrkbuild, env, f"{port_name}:pre-build")

        if recipe.get("build_cmd"):
            for bcmd in recipe["build_cmd"]:
                run_step(bcmd, wrkbuild, env, f"{port_name}:build")
        elif style == "cmake":
            run_step(["cmake", "--build", str(wrkbuild), "-j", str(jobs), *exp_args(recipe.get("make_args", []))], wrkbuild, env, f"{port_name}:cmake-build")
        else:
            m_cmd = [make_prog, f"-j{jobs}", *exp_args(recipe.get("make_args", [])), *exp_args(recipe.get("make_targets", []))]
            run_step(m_cmd, wrkbuild, env, f"{port_name}:make")

        if recipe.get("install_cmd"):
            for icmd in recipe["install_cmd"]:
                run_step(icmd, wrkbuild, env, f"{port_name}:install")
        elif style == "cmake":
            inst_env = dict(env)
            inst_env["DESTDIR"] = str(stage_dir)
            run_step(["cmake", "--install", str(wrkbuild)], wrkbuild, inst_env, f"{port_name}:cmake-install")
        else:
            inst_target = recipe.get("install_target", "install")
            if inst_target:
                use_destdir = recipe.get("install_use_destdir", True)
                dest_args = [f"DESTDIR={stage_dir}"] if use_destdir else [f"PREFIX={stage_dir}/usr/local"]
                i_cmd = [make_prog, inst_target, *dest_args, *exp_args(recipe.get("install_args", []))]
                run_step(i_cmd, wrkbuild, env, f"{port_name}:install")

    for hook in recipe.get("post_install", []):
        run_step(hook, wrkbuild, env, f"{port_name}:post-install")

    after_snap = snapshot_tree(stage_dir)
    installed_files = sorted(
        rel for rel, meta in after_snap.items() if before_snap.get(rel) != meta
    )

    record: Dict[str, Any] = {
        "port": port_name,
        "vendor_port": vport,
        "pkgname": pkgname,
        "section": section,
        "openbsd_version": openbsd_version,
        "backend": backend,
        "pal": pal,
        "signature": build_sig,
        "installed_files": installed_files,
        "applets": recipe.get("applets", []),
    }
    if sdk:
        record["sdk"] = sdk
    comment, descr = get_port_comment_and_descr(vendor_ports_dir, vport, port_dir, section)
    if comment:
        record["comment"] = comment
    if descr:
        record["descr"] = descr
    stamp_file.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"[build/{openbsd_version}] finished {port_name} ({pkgname}): {len(installed_files)} staged entries")
    return record


def resolve_obsd_root_arg(arg_val: Optional[str]) -> pathlib.Path:
    if arg_val:
        p = pathlib.Path(arg_val).resolve()
        if not (p / "vendor/openbsd/versions").is_dir():
            die(f"invalid --libobsdcompat-root: {p}")
        return p
    proc = subprocess.run(
        ["sh", str(REPO_ROOT / "tools/config/locate-libobsdcompat.sh")],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit(proc.returncode)
    return pathlib.Path(proc.stdout.strip()).resolve()


def resolve_build_lane_dir(openbsd_version: str, backend: str, pal: str, build_root_arg: str = "") -> pathlib.Path:
    raw = build_root_arg.strip() or os.environ.get("BUILD_ROOT", "").strip()
    base = pathlib.Path(raw).resolve() if raw else (REPO_ROOT / "build")
    return base / "openbsd" / openbsd_version / backend / pal


def cmd_list_catalog(args: argparse.Namespace) -> int:
    cat_path = REPO_ROOT / "config/versions" / f"{args.openbsd_version}-catalog.tsv"
    if not cat_path.is_file():
        die(f"missing catalog {cat_path}; run `make sync-vendor` first")
    flt = (args.filter or "").strip().lower()
    shown = 0
    for idx, raw in enumerate(cat_path.read_text(encoding="utf-8").splitlines()):
        if idx == 0 or not raw.strip() or raw.startswith("#"):
            continue
        if raw.startswith("portpath\t"):
            continue
        if flt and flt not in raw.lower():
            continue
        cols = raw.split("\t")
        portpath = cols[0]
        pkgname = cols[1] if len(cols) > 1 else ""
        comment = cols[3] if len(cols) > 3 else ""
        print(f"{portpath:<32} {pkgname:<28} {comment}")
        shown += 1
    print(f"# OpenBSD {args.openbsd_version} catalog: {shown} matching port(s)")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    sdk = resolve_lane_sdk(args.pal, args.backend, args.sdk)
    recipes = discover_recipes(
        args.openbsd_version,
        [args.port] if args.port else None,
        backend=args.backend,
        pal=args.pal,
        section=args.section,
        include_cross_section_deps=bool(args.port),
    )
    lane_dir = compute_lane_dir(args.openbsd_version, args.backend, args.pal, sdk, args.build_root)
    vendor_ports_dir = REPO_ROOT / "vendor/openbsd/versions" / args.openbsd_version / "ports"

    if not recipes:
        sec_lbl = "ports/ or extra/" if args.section == "all" else f"{args.section}/"
        print(f"# No port recipes under {sec_lbl} yet (lane: OpenBSD {args.openbsd_version} {args.backend}/{args.pal})")
        return 0

    print(f"{'PORT':<24} {'PKGNAME':<24} {'VENDOR':<10} {'STATUS':<10} {'APPLETS'}")
    for rec in recipes:
        pname = rec["port"]
        sec = rec.get("section", "ports")
        pdir: pathlib.Path = rec["port_dir"]
        if sec == "extra":
            has_meta = "extra" if (pdir / "distinfo").is_file() else "missing"
            pkgname = rec.get("pkgname") or (
                get_port_pkgname(vendor_ports_dir, rec["vendor_port"], port_dir=pdir, section="extra")
                if (pdir / "Makefile").is_file()
                else "-"
            )
        else:
            vdir = vendor_ports_dir / rec["vendor_port"]
            has_meta = "imported" if (vdir / "distinfo").is_file() else "missing"
            pkgname = rec.get("pkgname") or (
                get_port_pkgname(vendor_ports_dir, rec["vendor_port"], port_dir=pdir, section="ports")
                if has_meta == "imported"
                else "-"
            )
        stamp = lane_dir / ".stamps" / (pname.replace("/", "__") + ".json")
        status = "built" if stamp.is_file() else "pending"
        app_names = ",".join(a.get("sym", "") for a in rec.get("applets", [])) or "(lib)"
        print(f"{pname:<24} {pkgname:<24} {has_meta:<10} {status:<10} {app_names}")
    return 0


def cmd_fetch(args: argparse.Namespace) -> int:
    recipes = discover_recipes(
        args.openbsd_version,
        [args.port] if args.port else None,
        backend=args.backend,
        pal=args.pal,
        section=args.section,
        include_cross_section_deps=True,
    )
    if not recipes:
        print(f"[fetch/{args.openbsd_version}] 0 port recipes in section '{args.section}' (nothing to fetch)")
        return 0
    for rec in recipes:
        fetch_port_distfiles(rec, args.openbsd_version, jobs=args.jobs)
    return 0


def require_libobsdcompat_lane_outputs(
    obsd_root: pathlib.Path, openbsd_version: str, backend: str, pal: str, sdk: str = ""
) -> None:
    """obsd-ports consumes libobsdcompat build outputs; it never builds them."""
    if pal == "emscripten":
        wasm_dir = obsd_root / f"build/wasm-{openbsd_version}"
        need = [
            obsd_root / "deps/emsdk/upstream/emscripten/emcc",
            wasm_dir / f"include-root-{openbsd_version}",
            wasm_dir / f"libobsdc-wasm-{openbsd_version}.a",
        ]
        missing = [str(p) for p in need if not p.exists()]
        if missing:
            die(
                "missing libobsdcompat emscripten outputs for OpenBSD "
                f"{openbsd_version}:\n  " + "\n  ".join(missing) + "\n"
                "build them first (base guest before ports):\n"
                f"  make -C {obsd_root} COMPAT_BACKEND=emulate COMPAT_PAL=emscripten "
                f"OPENBSD_VERSION={openbsd_version} wasm-emsdk wasm-guest\n"
                f"  (sonvori-terminal: make web-wasm RELEASE={openbsd_version} WEB_WASM_ARGS=--without-ports)"
            )
        return

    if pal == "darwin":
        if backend == "translate":
            need = [
                obsd_root / f"build/openbsd/{openbsd_version}/translate/gen/guest-configure/tool-probe-vector.tsv",
                obsd_root / f"build/openbsd-boundary/obj-{openbsd_version}-kern-gate/libobsdc-{openbsd_version}.a",
                obsd_root / f"build/openbsd-boundary/include-roots/{openbsd_version}-kern-gate/compiler-include-root-{openbsd_version}-kern-gate",
            ]
        else:
            need = [
                obsd_root / f"build/openbsd-boundary/obj-{openbsd_version}-kern-gate-emulate-{sdk}/libobsdc-{openbsd_version}.a",
                obsd_root / f"build/openbsd-boundary/obj-{openbsd_version}-kern-gate-emulate-{sdk}/.object-build-identity",
                obsd_root / f"build/openbsd-boundary/include-roots/{openbsd_version}-kern-gate-emulate-{sdk}/compiler-include-root-{openbsd_version}-kern-gate-emulate-{sdk}",
            ]
        missing = [str(p) for p in need if not p.exists()]
        if missing:
            die(
                f"missing libobsdcompat Darwin ({backend}/{sdk}) outputs for OpenBSD {openbsd_version}:\n  "
                + "\n  ".join(missing)
                + f"\n  (sonvori-terminal: scripts/build-backend.sh --sdk {sdk} --release {openbsd_version})"
            )


def cmd_build(args: argparse.Namespace) -> int:
    sdk = resolve_lane_sdk(args.pal, args.backend, args.sdk)
    obsd_root = resolve_obsd_root_arg(args.libobsdcompat_root)
    require_libobsdcompat_lane_outputs(obsd_root, args.openbsd_version, args.backend, args.pal, sdk)
    if args.pal == "emscripten":
        obsd_env.ensure_emsdk_python(obsd_root)
    recipes = discover_recipes(
        args.openbsd_version,
        [args.port] if args.port else None,
        backend=args.backend,
        pal=args.pal,
        section=args.section,
        include_cross_section_deps=True,
    )
    lane_dir = compute_lane_dir(args.openbsd_version, args.backend, args.pal, sdk, args.build_root)
    lane_dir.mkdir(parents=True, exist_ok=True)
    if not recipes:
        print(f"[build/{args.openbsd_version}] 0 port recipes in section '{args.section}' (nothing to build)")
        return 0
    for rec in recipes:
        build_single_port(
            recipe=rec,
            openbsd_version=args.openbsd_version,
            backend=args.backend,
            pal=args.pal,
            sdk=sdk,
            obsd_root=obsd_root,
            lane_dir=lane_dir,
            jobs=args.jobs,
            force=args.force,
        )
    return 0


def cmd_package(args: argparse.Namespace) -> int:
    sdk = resolve_lane_sdk(args.pal, args.backend, args.sdk)
    obsd_root = resolve_obsd_root_arg(args.libobsdcompat_root)
    require_libobsdcompat_lane_outputs(obsd_root, args.openbsd_version, args.backend, args.pal, sdk)
    if args.pal == "emscripten":
        obsd_env.ensure_emsdk_python(obsd_root)
    lane_dir = compute_lane_dir(args.openbsd_version, args.backend, args.pal, sdk, args.build_root)
    lane_dir.mkdir(parents=True, exist_ok=True)

    adapter_script = REPO_ROOT / "targets" / args.backend / args.pal / f"package_{'wasm' if args.pal in ('emscripten', 'wasi') else args.pal}.py"
    if not adapter_script.is_file():
        adapter_script = REPO_ROOT / "targets" / args.backend / args.pal / "package.py"
    if not adapter_script.is_file():
        die(f"target packaging adapter not implemented for {args.backend}/{args.pal}: expected {adapter_script}")

    # INVARIANT: ALWAYS assemble `built-ports.json` across `section="all"` so
    # `make package SECTION=extra` never drops previously built `ports/*` applets!
    all_recipes = discover_recipes(
        args.openbsd_version,
        None,
        backend=args.backend,
        pal=args.pal,
        section="all",
    )
    vendor_ports_dir = REPO_ROOT / "vendor/openbsd/versions" / args.openbsd_version / "ports"
    manifest_file = lane_dir / "built-ports.json"
    stamps_dir = lane_dir / ".stamps"
    records = []
    for rec in all_recipes:
        st_path = stamps_dir / (rec["port"].replace("/", "__") + ".json")
        if st_path.is_file():
            data = json.loads(st_path.read_text(encoding="utf-8"))
            sec = rec.get("section", "ports")
            data["section"] = sec
            data["applets"] = rec.get("applets", [])
            if not data.get("comment") or not data.get("descr"):
                comment, descr = get_port_comment_and_descr(
                    vendor_ports_dir,
                    rec["vendor_port"],
                    rec["port_dir"],
                    sec,
                )
                if comment and not data.get("comment"):
                    data["comment"] = comment
                if descr and not data.get("descr"):
                    data["descr"] = descr
            records.append(data)
    manifest_file.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")

    cmd = [
        sys.executable,
        "-I",
        str(adapter_script),
        "--openbsd-version",
        args.openbsd_version,
        "--backend",
        args.backend,
        "--pal",
        args.pal,
        *(["--sdk", sdk] if sdk else []),
        "--libobsdcompat-root",
        str(obsd_root),
        "--lane-dir",
        str(lane_dir),
        "--manifest",
        str(manifest_file),
    ]
    return subprocess.run(cmd).returncode


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="subcmd", required=True)

    p_cat = sub.add_parser("list-catalog")
    default_ver = obsd_versions.default_version()
    p_cat.add_argument("--openbsd-version", default=default_ver)
    p_cat.add_argument("--filter", default="")

    for name in ("list", "fetch", "build", "package"):
        sp = sub.add_parser(name)
        sp.add_argument("--openbsd-version", default=default_ver)
        sp.add_argument("--backend", default="emulate")
        sp.add_argument("--pal", default="emscripten")
        sp.add_argument("--section", default="all", choices=("all", "ports", "extra"))
        sp.add_argument("--build-root", default="")
        sp.add_argument("--sdk", default="")
        sp.add_argument("--libobsdcompat-root", default="")
        sp.add_argument("--port", default="")
        sp.add_argument("--jobs", type=int, default=os.cpu_count() or 8)
        if name == "build":
            sp.add_argument("--force", action="store_true")

    args = ap.parse_args()
    if getattr(args, "libobsdcompat_root", "") and getattr(args, "pal", "emscripten") == "emscripten":
        obsd_env.ensure_emsdk_python(args.libobsdcompat_root)
    try:
        obsd_versions.require_verified(args.openbsd_version)
    except obsd_versions.ReleaseConfigError as exc:
        die(str(exc), 2)
    if args.subcmd == "list-catalog":
        return cmd_list_catalog(args)
    if args.subcmd == "list":
        return cmd_list(args)
    if args.subcmd == "fetch":
        return cmd_fetch(args)
    if args.subcmd == "build":
        return cmd_build(args)
    if args.subcmd == "package":
        return cmd_package(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
