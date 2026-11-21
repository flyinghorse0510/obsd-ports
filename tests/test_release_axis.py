#!/usr/bin/env python3
"""
test_release_axis.py -- Release-axis regression checks (no emsdk / build needed).

1. `config/versions/index.tsv` and every `config/versions/<v>.mk` agree
   (osrev_int, api_hex, ports URL/SHA256).
2. The `osrev_int` of every release that has ever shipped matches the value
   OpenBSD's own `sys/sys/param.h` `#define OpenBSD` carried for it. This pins
   historical facts (7.9 is 202605, not 202604), not the active release list.
3. When libobsdcompat is declared, each release is also `verified` in
   libobsdcompat's `config/personalities/openbsd/versions/index.tsv` and its
   vendor `sys/sys/param.h` agrees with `osrev_int`.
4. The default release is the newest verified one, `resolve_versions()` accepts
   comma- and space-separated lists, and unknown releases are rejected.

Stdlib-only; runs on Python >= 3.9.
"""
from __future__ import annotations

import argparse
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools/config"))
import obsd_versions  # noqa: E402

# `#define OpenBSD` from each release's sys/sys/param.h (historical facts).
KNOWN_OSREV = {
    "7.8": 202510,
    "7.9": 202605,
    "8.0": 202610,
}


def fail(msg: str) -> "NoReturn":
    sys.stderr.write(f"test_release_axis: FAIL: {msg}\n")
    raise SystemExit(1)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--libobsdcompat-root", default="")
    args = ap.parse_args()

    errs = obsd_versions.check_repo_consistency()
    if errs:
        fail("; ".join(errs))

    vers = obsd_versions.verified_versions()
    for v in vers:
        if v in KNOWN_OSREV and obsd_versions.osrev_int(v) != KNOWN_OSREV[v]:
            fail(f"{v}: osrev_int {obsd_versions.osrev_int(v)} != OpenBSD param.h {KNOWN_OSREV[v]}")
    osrevs = [obsd_versions.osrev_int(v) for v in vers]
    if osrevs != sorted(osrevs) or len(set(osrevs)) != len(osrevs):
        fail(f"osrev_int must increase strictly with the release: {dict(zip(vers, osrevs))}")

    if obsd_versions.default_version() != vers[-1]:
        fail(f"default {obsd_versions.default_version()} is not the newest verified release {vers[-1]}")
    if obsd_versions.resolve_versions("all") != vers or obsd_versions.resolve_versions("") != vers:
        fail("resolve_versions('all'/'') must return every verified release")
    if len(vers) >= 2:
        pair = vers[-2:]
        for spec in (",".join(pair), " ".join(pair), f" {pair[0]} ,{pair[1]} "):
            if obsd_versions.resolve_versions(spec) != pair:
                fail(f"resolve_versions({spec!r}) != {pair}")
    try:
        obsd_versions.resolve_versions("0.1")
    except obsd_versions.ReleaseConfigError:
        pass
    else:
        fail("resolve_versions accepted an undeclared release")

    root = pathlib.Path(args.libobsdcompat_root).resolve() if args.libobsdcompat_root else obsd_versions._locate_libobsdcompat_quiet()
    if root is not None:
        errs = obsd_versions.check_against_libobsdcompat(root)
        if errs:
            fail("; ".join(errs))
        cross = f"; cross-checked against {root}"
    else:
        cross = "; libobsdcompat not declared, vendor cross-check skipped"

    print(f"test_release_axis: OK ({', '.join(f'{v}={o}' for v, o in zip(vers, osrevs))}; default {vers[-1]}{cross})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
