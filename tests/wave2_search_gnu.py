#!/usr/bin/env python3
"""
tests/wave2_search_gnu.py -- Dual-Release (OpenBSD 7.8 + 7.9) WASM64 Verification
Suite for Wave-2 Slice B (Code Search, GNU Text/Regex, XML & Markdown):
  1. sysutils/ugrep (`ugrep`, `ug`, `ugrep-indexer`) -- C++11 PCRE2 + `-z` archive search
  2. textproc/the_silver_searcher (`ag`) -- PCRE1 + LZMA/zlib recursive code search
  3. sysutils/ggrep (`ggrep`, `gegrep`, `gfgrep`) -- GNU grep + PCRE2 lookahead/lookbehind
  4. textproc/gsed (`gsed`) -- GNU sed `-i` in-place extended regex & case transforms
  5. lang/gawk (`gawk`) -- GNU awk `BEGINFILE`, associative arrays, and `gensub()`
  6. textproc/lowdown (`lowdown`, `lowdown-diff`, `liblowdown.a`) -- ANSI `-tterm` & `-thtml`
  7. textproc/libxml (`xmllint`, `xmlcatalog`, `libxml2.a`) -- `--xpath`, `--format` & iconv
  8. converters/dos2unix (`dos2unix`, `mac2unix`, `unix2dos`, `unix2mac`) -- CRLF/CR <-> LF
"""
from __future__ import annotations

import argparse
import gzip
import os
import pathlib
import subprocess
import sys
import tempfile
import time
from typing import List, Set

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools/config"))
import obsd_versions  # noqa: E402  (release axis from config/versions/index.tsv)

EXPECTED_APPLETS = {
    "/usr/local/bin/ugrep",
    "/usr/local/bin/ug",
    "/usr/local/bin/ugrep-indexer",
    "/usr/local/bin/ag",
    "/usr/local/bin/ggrep",
    "/usr/local/bin/gsed",
    "/usr/local/bin/gawk",
    "/usr/local/bin/lowdown",
    "/usr/local/bin/lowdown-diff",
    "/usr/local/bin/xmllint",
    "/usr/local/bin/xmlcatalog",
    "/usr/local/bin/dos2unix",
    "/usr/local/bin/mac2unix",
    "/usr/local/bin/unix2dos",
    "/usr/local/bin/unix2mac",
}

EXPECTED_WRAPPERS = [
    "usr/local/bin/gegrep",
    "usr/local/bin/gfgrep",
]

EXPECTED_LIBS = [
    "usr/local/lib/liblowdown.a",
    "usr/local/lib/libxml2.a",
]

EXPECTED_PCS = [
    "usr/local/lib/pkgconfig/lowdown.pc",
    "usr/local/lib/pkgconfig/libxml-2.0.pc",
]


def resolve_obsd_root(cli_val: str = "") -> pathlib.Path:
    if cli_val:
        return pathlib.Path(cli_val).resolve()
    env_val = os.environ.get("LIBOBSDCOMPAT_ROOT", "").strip()
    if env_val:
        return pathlib.Path(env_val).resolve()
    out = subprocess.check_output(
        ["sh", str(REPO_ROOT / "tools/config/locate-libobsdcompat.sh")],
        text=True,
    ).strip()
    return pathlib.Path(out).resolve()


def bytes_to_octal_printf(data: bytes) -> str:
    return "".join(f"\\{b:03o}" for b in data)


def verify_packaged_artifacts(ver: str, lane_dir: pathlib.Path) -> None:
    tsv_path = lane_dir / "ports-applets.tsv"
    if not tsv_path.is_file():
        raise AssertionError(f"[{ver}] missing {tsv_path}; run `make package OPENBSD_VERSION={ver}` first")

    applet_paths: Set[str] = set()
    for raw in tsv_path.read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        cols = s.split("\t")
        if len(cols) >= 4:
            applet_paths.add(cols[1])
            obj_p = lane_dir / cols[3]
            if not obj_p.is_file():
                raise AssertionError(f"[{ver}] missing localized applet object: {obj_p}")

    missing = sorted(EXPECTED_APPLETS - applet_paths)
    if missing:
        raise AssertionError(f"[{ver}] missing expected applets in ports-applets.tsv: {missing}")

    if "/usr/local/bin/awk" in applet_paths or (lane_dir / "sysroot/usr/local/bin/awk").exists():
        raise AssertionError(f"[{ver}] /usr/local/bin/awk must not be staged (would shadow base /usr/bin/awk)")

    sysroot = lane_dir / "sysroot"
    for rel in EXPECTED_WRAPPERS + EXPECTED_LIBS + EXPECTED_PCS:
        p = sysroot / rel
        if not p.is_file():
            raise AssertionError(f"[{ver}] missing expected sysroot file: {p}")

    print(f"[WAVE2-SEARCH-GNU/{ver}] packaging & sysroot artifacts verified ({len(EXPECTED_APPLETS)} applet paths)")


LIB_CLOSURE_PROBE_C = r"""
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <lowdown.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>

int main(void) {
    struct lowdown_opts opts;
    memset(&opts, 0, sizeof(opts));
    opts.type = LOWDOWN_HTML;
    char *out = NULL;
    size_t outsz = 0;
    if (!lowdown_buf(&opts, "# Hello\n", 8, &out, &outsz, NULL))
        return 1;
    free(out);

    const char *xml = "<root><item>ok</item></root>";
    xmlDocPtr doc = xmlReadMemory(xml, (int)strlen(xml), "mem.xml", NULL, 0);
    if (!doc)
        return 2;
    xmlXPathContextPtr ctx = xmlXPathNewContext(doc);
    xmlXPathObjectPtr res = xmlXPathEvalExpression((const xmlChar *)"string(/root/item)", ctx);
    int ok = (res && res->stringval && strcmp((const char *)res->stringval, "ok") == 0);
    if (res)
        xmlXPathFreeObject(res);
    if (ctx)
        xmlXPathFreeContext(ctx);
    xmlFreeDoc(doc);
    xmlCleanupParser();
    return ok ? 0 : 3;
}
"""


def verify_static_libs_sdk_link(ver: str, obsd_root: pathlib.Path, lane_dir: pathlib.Path) -> None:
    obsd_cc = REPO_ROOT / "sdk/bin/obsd-cc"
    obsd_pkg_cfg = REPO_ROOT / "sdk/bin/obsd-pkg-config"
    env = dict(os.environ)
    env["OPENBSD_VERSION"] = ver
    env["LIBOBSDCOMPAT_ROOT"] = str(obsd_root)
    env["OBSD_STAGE_DIR"] = str(lane_dir / "stage")

    cflags = subprocess.check_output(
        [str(obsd_pkg_cfg), "--cflags", "lowdown", "libxml-2.0"],
        env=env,
        text=True,
    ).split()
    libs = subprocess.check_output(
        [str(obsd_pkg_cfg), "--libs", "--static", "lowdown", "libxml-2.0"],
        env=env,
        text=True,
    ).split()

    with tempfile.TemporaryDirectory(prefix=f"obsd-w2-libprobe-{ver}-") as td:
        tp = pathlib.Path(td)
        c_file = tp / "probe.c"
        o_out = tp / "probe"
        c_file.write_text(LIB_CLOSURE_PROBE_C, encoding="utf-8")
        subprocess.run(
            [str(obsd_cc), *cflags, str(c_file), *libs, "-o", str(o_out)],
            env=env,
            check=True,
        )
        assert o_out.is_file() and o_out.stat().st_size > 0

    print(f"[WAVE2-SEARCH-GNU/{ver}] SDK static link closure (liblowdown.a + libxml2.a + .pc): PASS")


GUEST_SCRIPT_TEMPLATE = r"""
EXPECTED_REL="__OPENBSD_VERSION__"

fail() {
    echo "[W2-FAIL] $*"
    exit 1
}

pass() {
    echo "[W2-PASS] $1: $2"
}

OS_SYS=$(uname -s)
OS_REL=$(uname -r)
[ "$OS_SYS" = "OpenBSD" ] || fail "expected OpenBSD, got $OS_SYS"
[ "$OS_REL" = "$EXPECTED_REL" ] || fail "expected $EXPECTED_REL, got $OS_REL"

# Verify PATH resolution & absence of /usr/local/bin/awk
[ ! -e /usr/local/bin/awk ] || fail "/usr/local/bin/awk exists and would shadow base awk"
for b in ugrep ug ugrep-indexer ag ggrep gegrep gfgrep gsed gawk lowdown lowdown-diff xmllint xmlcatalog dos2unix mac2unix unix2dos unix2mac; do
    p=$(command -v "$b") || fail "missing command $b"
    [ "$p" = "/usr/local/bin/$b" ] || fail "unexpected path for $b: $p"
done
pass "01_binaries_and_wrappers" "OpenBSD $OS_REL; all 17 binaries/wrappers resolved in /usr/local/bin"

rm -rf /tmp/w2
mkdir -p /tmp/w2/src/sub /tmp/w2/archives

cat > /tmp/w2/src/alpha.c <<'EOF'
#include <stdio.h>
/* SONVORI_TOKEN_42 inside C source */
int compute_magic(void) {
    return 42;
}
EOF

cat > /tmp/w2/src/sub/beta.h <<'EOF'
#ifndef BETA_H
#define BETA_H
#define SONVORI_TOKEN_99 "wasm64_lp64_safe"
#define IGNORED_DRAFT "skip_me"
#endif
EOF

cat > /tmp/w2/src/.gitignore <<'EOF'
ignored_file.c
EOF

cat > /tmp/w2/src/ignored_file.c <<'EOF'
/* SONVORI_TOKEN_777 should be ignored by ag/ugrep --ignore-files */
EOF

# 02. sysutils/ugrep (C++11 PCRE2, -z compressed archives .gz/.xz/.zst/.bz2/.lz4, indexer, repeated MALLOC_OPTIONS=JJ runs)
UG_VER=$(MALLOC_OPTIONS=JJ ugrep --version)
echo "$UG_VER" | grep -qi "pcre2" || fail "ugrep missing pcre2 in --version: $UG_VER"
echo "$UG_VER" | grep -qi "zlib" || fail "ugrep missing zlib in --version: $UG_VER"
echo "$UG_VER" | grep -qi "bzip2" || fail "ugrep missing bzip2 in --version: $UG_VER"
echo "$UG_VER" | grep -qi "lzma" || fail "ugrep missing lzma in --version: $UG_VER"
echo "$UG_VER" | grep -qi "zstd" || fail "ugrep missing zstd in --version: $UG_VER"
echo "$UG_VER" | grep -qi "lz4" || fail "ugrep missing lz4 in --version: $UG_VER"

UG_R1=$(MALLOC_OPTIONS=JJ ugrep --no-color -rn -P 'SONVORI_(?=TOKEN_[0-9]+)' --ignore-files /tmp/w2/src | sort)
UG_R2=$(MALLOC_OPTIONS=JJ ugrep --no-color -rn -P 'SONVORI_(?=TOKEN_[0-9]+)' --ignore-files /tmp/w2/src | sort)
UG_R3=$(MALLOC_OPTIONS=JJ ug --no-color -rn -P 'SONVORI_(?=TOKEN_[0-9]+)' --ignore-files /tmp/w2/src | sort)
[ "$UG_R1" = "$UG_R2" ] || fail "ugrep repeated run mismatch: $UG_R1 vs $UG_R2"
[ "$UG_R1" = "$UG_R3" ] || fail "ug alias output mismatch: $UG_R1 vs $UG_R3"
echo "$UG_R1" | grep -q "alpha.c:2:.*SONVORI_TOKEN_42" || fail "ugrep missed alpha.c: $UG_R1"
echo "$UG_R1" | grep -q "beta.h:3:.*SONVORI_TOKEN_99" || fail "ugrep missed beta.h: $UG_R1"
if echo "$UG_R1" | grep -q "777"; then
    fail "ugrep did not respect .gitignore: $UG_R1"
fi

# Create .gz, .xz, .zst, .bz2, .lz4 archives and search inside all of them with `ugrep -z`
printf '__GZ_OCTAL__' > /tmp/w2/archives/note_gz.txt.gz
printf 'header\nARCHIVE_SECRET_XZ=ok_xz\nfooter\n' | MALLOC_OPTIONS=JJ xz -c > /tmp/w2/archives/note_xz.txt.xz
printf 'header\nARCHIVE_SECRET_ZST=ok_zst\nfooter\n' | MALLOC_OPTIONS=JJ zstd -q -c > /tmp/w2/archives/note_zst.txt.zst
printf 'header\nARCHIVE_SECRET_BZ2=ok_bz2\nfooter\n' | MALLOC_OPTIONS=JJ bzip2 -c > /tmp/w2/archives/note_bz2.txt.bz2
printf 'header\nARCHIVE_SECRET_LZ4=ok_lz4\nfooter\n' | MALLOC_OPTIONS=JJ lz4 -q -c > /tmp/w2/archives/note_lz4.txt.lz4

UG_Z1=$(MALLOC_OPTIONS=JJ ugrep --no-color -z -rn -P 'ARCHIVE_(?=SECRET_[A-Z0-9]+)' /tmp/w2/archives | sort)
UG_Z2=$(MALLOC_OPTIONS=JJ ugrep --no-color -z -rn -P 'ARCHIVE_(?=SECRET_[A-Z0-9]+)' /tmp/w2/archives | sort)
[ "$UG_Z1" = "$UG_Z2" ] || fail "ugrep -z repeated run mismatch"
for tag in ARCHIVE_SECRET_GZ=ok_gz ARCHIVE_SECRET_XZ=ok_xz ARCHIVE_SECRET_ZST=ok_zst ARCHIVE_SECRET_BZ2=ok_bz2 ARCHIVE_SECRET_LZ4=ok_lz4; do
    echo "$UG_Z1" | grep -q "$tag" || fail "ugrep -z missed $tag in: $UG_Z1"
done

MALLOC_OPTIONS=JJ ugrep-indexer -q -I /tmp/w2/src
[ -s /tmp/w2/src/._UG#_Store ] || fail "ugrep-indexer did not create ._UG#_Store"
UG_IDX=$(MALLOC_OPTIONS=JJ ugrep --no-color --index -rn 'SONVORI_TOKEN_42' /tmp/w2/src)
echo "$UG_IDX" | grep -q "alpha.c:2:" || fail "ugrep --index search failed: $UG_IDX"
MALLOC_OPTIONS=JJ ugrep-indexer -q -d /tmp/w2/src
pass "02_ugrep_pcre2_archives_and_cxx_ctors" "ugrep/ug/ugrep-indexer verified on .gz/.xz/.zst/.bz2/.lz4 + 5x MALLOC_OPTIONS=JJ C++ runs"

# 03. textproc/the_silver_searcher (ag recursive code search + .gitignore + lzma/zlib)
AG_OUT1=$(MALLOC_OPTIONS=JJ ag --vimgrep --nocolor --workers=2 'SONVORI_TOKEN_[0-9]+' /tmp/w2/src | sort)
AG_OUT2=$(MALLOC_OPTIONS=JJ ag --vimgrep --nocolor --workers=2 'SONVORI_TOKEN_[0-9]+' /tmp/w2/src | sort)
[ "$AG_OUT1" = "$AG_OUT2" ] || fail "ag repeated run mismatch"
echo "$AG_OUT1" | grep -q "alpha.c:2:.*SONVORI_TOKEN_42" || fail "ag missed alpha.c: $AG_OUT1"
echo "$AG_OUT1" | grep -q "beta.h:3:.*SONVORI_TOKEN_99" || fail "ag missed beta.h: $AG_OUT1"
if echo "$AG_OUT1" | grep -q "777"; then
    fail "ag did not honor .gitignore: $AG_OUT1"
fi
AG_Z=$(MALLOC_OPTIONS=JJ ag --nogroup --nocolor -z 'ARCHIVE_SECRET_XZ' /tmp/w2/archives/note_xz.txt.xz)
echo "$AG_Z" | grep -q "ARCHIVE_SECRET_XZ=ok_xz" || fail "ag -z xz search failed: $AG_Z"
pass "03_ag_silver_searcher" "ag recursive multithreaded PCRE search + .gitignore + -z xz verified"

# 04. sysutils/ggrep (ggrep -P PCRE2 lookahead/lookbehind + gegrep/gfgrep wrappers)
GG_IN="id=100 foo_skip id=205 foobar_ok key=sonvori64 tail"
GG_P1=$(printf '%s\n' "$GG_IN" | MALLOC_OPTIONS=JJ ggrep -oP 'foo(?=bar_ok)|(?<=key=)[a-z0-9]+')
GG_P2=$(printf '%s\n' "$GG_IN" | MALLOC_OPTIONS=JJ ggrep -oP 'foo(?=bar_ok)|(?<=key=)[a-z0-9]+')
EXPECTED_GG=$(printf 'foo\nsonvori64')
[ "$GG_P1" = "$EXPECTED_GG" ] || fail "ggrep -P lookahead/lookbehind mismatch: $GG_P1"
[ "$GG_P1" = "$GG_P2" ] || fail "ggrep repeated run mismatch"

GE_OUT=$(printf 'alpha\nbeta-789\ngamma\n' | MALLOC_OPTIONS=JJ gegrep '^(beta|delta)-[0-9]+$')
[ "$GE_OUT" = "beta-789" ] || fail "gegrep wrapper failed: $GE_OUT"
GF_OUT=$(printf 'a.*b\nliteral[1]\n' | MALLOC_OPTIONS=JJ gfgrep 'literal[1]')
[ "$GF_OUT" = "literal[1]" ] || fail "gfgrep wrapper failed: $GF_OUT"
pass "04_ggrep_pcre2_and_wrappers" "ggrep -P lookahead/lookbehind + gegrep/gfgrep verified"

# 05. textproc/gsed (gsed -i in-place GNU regex + \U case conversion)
cat > /tmp/w2/gsed_doc.txt <<'EOF'
pkg=ugrep version=7.6 status=draft
pkg=libxml version=2.15 status=draft
EOF
MALLOC_OPTIONS=JJ gsed -i -E 's/version=([0-9]+)\.([0-9]+)/rel=\1_\2/g; 2s/status=([a-z]+)/status=\U\1/' /tmp/w2/gsed_doc.txt
GSED_L1=$(sed -n '1p' /tmp/w2/gsed_doc.txt)
GSED_L2=$(sed -n '2p' /tmp/w2/gsed_doc.txt)
[ "$GSED_L1" = "pkg=ugrep rel=7_6 status=draft" ] || fail "gsed -i line 1 mismatch: $GSED_L1"
[ "$GSED_L2" = "pkg=libxml rel=2_15 status=DRAFT" ] || fail "gsed -i line 2 mismatch: $GSED_L2"
pass "05_gsed_inplace_gnu_regex" "gsed -i -E capture groups and \\U uppercase verified"

# 06. lang/gawk (associative arrays, gensub, BEGINFILE/ENDFILE)
cat > /tmp/w2/f1.dat <<'EOF'
search=10
gnu=25
EOF
cat > /tmp/w2/f2.dat <<'EOF'
search=15
xml=30
EOF
GAWK_OUT=$(MALLOC_OPTIONS=JJ gawk '
BEGINFILE { files++ }
{
    norm = gensub(/^([a-z]+)=([0-9]+)$/, "\\1|\\2", 1, $0)
    split(norm, parts, "|")
    sums[parts[1]] += parts[2] + 0
}
END {
    printf "files=%d;gnu=%d;search=%d;xml=%d\n", files, sums["gnu"], sums["search"], sums["xml"]
}
' /tmp/w2/f1.dat /tmp/w2/f2.dat)
[ "$GAWK_OUT" = "files=2;gnu=25;search=25;xml=30" ] || fail "gawk BEGINFILE/gensub/assoc mismatch: $GAWK_OUT"
pass "06_gawk_beginfile_gensub_assoc" "gawk BEGINFILE + associative arrays + gensub verified ($GAWK_OUT)"

# 07. textproc/lowdown (lowdown -tterm ANSI + lowdown -thtml + lowdown-diff)
cat > /tmp/w2/doc1.md <<'EOF'
# Sonvori Ports

- **ugrep** fast search
- `xmllint` parser
EOF
cat > /tmp/w2/doc2.md <<'EOF'
# Sonvori Ports

- **ugrep** ultra fast search
- `xmllint` XML parser
EOF

LD_HTML=$(MALLOC_OPTIONS=JJ lowdown -thtml /tmp/w2/doc1.md)
echo "$LD_HTML" | grep -q "<h1" || fail "lowdown -thtml missing <h1>: $LD_HTML"
echo "$LD_HTML" | grep -q "<strong>ugrep</strong>" || fail "lowdown -thtml missing <strong>: $LD_HTML"
echo "$LD_HTML" | grep -q "<code>xmllint</code>" || fail "lowdown -thtml missing <code>: $LD_HTML"

LD_TERM=$(MALLOC_OPTIONS=JJ lowdown -tterm /tmp/w2/doc1.md)
[ -n "$LD_TERM" ] || fail "lowdown -tterm produced empty output"
ESC_CHAR=$(printf '\033')
echo "$LD_TERM" | grep -q "$ESC_CHAR" || fail "lowdown -tterm missing ANSI escape codes"
echo "$LD_TERM" | grep -q "Sonvori Ports" || fail "lowdown -tterm missing heading text"

LD_DIFF=$(MALLOC_OPTIONS=JJ lowdown-diff -thtml /tmp/w2/doc1.md /tmp/w2/doc2.md)
echo "$LD_DIFF" | grep -q "<ins>" || fail "lowdown-diff missing <ins>: $LD_DIFF"
pass "07_lowdown_term_html_diff" "lowdown -tterm ANSI + -thtml + lowdown-diff verified"

# 08. textproc/libxml (xmllint --xpath, --format, iconv ISO-8859-1, xmlcatalog)
cat > /tmp/w2/compact.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?><catalog><port id="1" wave="2"><name>ugrep</name><lang>cxx11</lang></port><port id="2" wave="2"><name>lowdown</name><lang>c</lang></port><port id="3" wave="1"><name>jq</name><lang>c</lang></port></catalog>
EOF

XP_NAMES=$(MALLOC_OPTIONS=JJ xmllint --xpath '//port[@wave="2"]/name/text()' /tmp/w2/compact.xml | tr '\n' ' ' | sed 's/ *$//')
[ "$XP_NAMES" = "ugrep lowdown" ] || fail "xmllint --xpath names mismatch: '$XP_NAMES'"
XP_COUNT=$(MALLOC_OPTIONS=JJ xmllint --xpath 'count(//port[@wave="2"])' /tmp/w2/compact.xml)
[ "$XP_COUNT" = "2" ] || fail "xmllint --xpath count mismatch: '$XP_COUNT'"

FMT_XML=$(MALLOC_OPTIONS=JJ xmllint --format /tmp/w2/compact.xml)
FMT_LINES=$(printf '%s\n' "$FMT_XML" | wc -l | tr -d ' ')
[ "$FMT_LINES" -ge 10 ] || fail "xmllint --format expected >=10 lines, got $FMT_LINES"
printf '%s\n' "$FMT_XML" | MALLOC_OPTIONS=JJ xmllint --noout - || fail "xmllint failed to validate formatted XML"

# Test libiconv integration via ISO-8859-1 encoded XML
printf '<?xml version="1.0" encoding="ISO-8859-1"?><note>caf\351</note>\n' > /tmp/w2/latin1.xml
LATIN_UTF8=$(MALLOC_OPTIONS=JJ xmllint --encode UTF-8 /tmp/w2/latin1.xml | MALLOC_OPTIONS=JJ xmllint --xpath 'string(/note)' -)
[ "$LATIN_UTF8" = "$(printf 'caf\303\251')" ] || fail "xmllint ISO-8859-1 -> UTF-8 iconv mismatch: $LATIN_UTF8"

MALLOC_OPTIONS=JJ xmlcatalog --noout --create /tmp/w2/xmlcat.xml
MALLOC_OPTIONS=JJ xmlcatalog --noout --add public "-//Sonvori//DTD Test 1.0//EN" "file:///tmp/w2/test.dtd" /tmp/w2/xmlcat.xml
CAT_RES=$(MALLOC_OPTIONS=JJ xmlcatalog /tmp/w2/xmlcat.xml "-//Sonvori//DTD Test 1.0//EN")
[ "$CAT_RES" = "file:///tmp/w2/test.dtd" ] || fail "xmlcatalog lookup mismatch: $CAT_RES"
pass "08_libxml_xmllint_xpath_format_catalog" "xmllint --xpath/--format/ISO-8859-1 + xmlcatalog verified"

# 09. converters/dos2unix (unix2dos/dos2unix CRLF <-> LF & unix2mac/mac2unix CR <-> LF SHA256 round-trip)
printf 'line_one_alpha\nline_two_beta\nline_three_gamma\n' > /tmp/w2/eol_orig.txt
ORIG_SHA=$(/bin/sha256 -q /tmp/w2/eol_orig.txt)
ORIG_LEN=$(wc -c < /tmp/w2/eol_orig.txt | tr -d ' ')

cp /tmp/w2/eol_orig.txt /tmp/w2/eol_work.txt
MALLOC_OPTIONS=JJ unix2dos -q /tmp/w2/eol_work.txt
DOS_LEN=$(wc -c < /tmp/w2/eol_work.txt | tr -d ' ')
EXP_DOS_LEN=$((ORIG_LEN + 3))
[ "$DOS_LEN" -eq "$EXP_DOS_LEN" ] || fail "unix2dos expected $EXP_DOS_LEN bytes, got $DOS_LEN"

MALLOC_OPTIONS=JJ dos2unix -q /tmp/w2/eol_work.txt
RT_DOS_SHA=$(/bin/sha256 -q /tmp/w2/eol_work.txt)
[ "$RT_DOS_SHA" = "$ORIG_SHA" ] || fail "dos2unix round-trip SHA256 mismatch: $RT_DOS_SHA != $ORIG_SHA"

MALLOC_OPTIONS=JJ unix2mac -q /tmp/w2/eol_work.txt
CR_COUNT=$(tr -cd '\r' < /tmp/w2/eol_work.txt | wc -c | tr -d ' ')
LF_COUNT=$(tr -cd '\n' < /tmp/w2/eol_work.txt | wc -c | tr -d ' ')
[ "$CR_COUNT" -eq 3 ] && [ "$LF_COUNT" -eq 0 ] || fail "unix2mac expected 3 CR and 0 LF, got CR=$CR_COUNT LF=$LF_COUNT"

MALLOC_OPTIONS=JJ mac2unix -q /tmp/w2/eol_work.txt
RT_MAC_SHA=$(/bin/sha256 -q /tmp/w2/eol_work.txt)
[ "$RT_MAC_SHA" = "$ORIG_SHA" ] || fail "mac2unix round-trip SHA256 mismatch: $RT_MAC_SHA != $ORIG_SHA"
pass "09_dos2unix_crlf_cr_roundtrip" "unix2dos/dos2unix & unix2mac/mac2unix byte-exact SHA256 ($ORIG_SHA)"

echo "[W2-ALL-PASS] OpenBSD $OS_REL Wave-2 Slice B (8 ports) passed all checks!"
"""


def run_guest_suite(ver: str, obsd_root: pathlib.Path, lane_dir: pathlib.Path) -> None:
    merge_guest_py = REPO_ROOT / "targets/emulate/emscripten/merge_wasm_guest.py"
    gz_payload = gzip.compress(b"header\nARCHIVE_SECRET_GZ=ok_gz\nfooter\n", mtime=0)
    script_text = (
        GUEST_SCRIPT_TEMPLATE.replace("__OPENBSD_VERSION__", ver).replace(
            "__GZ_OCTAL__", bytes_to_octal_printf(gz_payload)
        )
    )

    with tempfile.NamedTemporaryFile("w", prefix=f"w2-search-gnu-{ver}-", suffix=".sh", delete=False, encoding="utf-8") as tf:
        tf.write(script_text)
        script_path = pathlib.Path(tf.name)

    try:
        proc = subprocess.run(
            [
                sys.executable,
                "-I",
                str(merge_guest_py),
                "run-guest",
                "--libobsdcompat-root",
                str(obsd_root),
                "--openbsd-version",
                ver,
                "--ports-lane-dir",
                str(lane_dir),
                "--script-file",
                str(script_path),
                "--timeout-ms",
                "180000",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    finally:
        script_path.unlink(missing_ok=True)

    sys.stdout.write(proc.stdout)
    sys.stdout.flush()

    if proc.returncode != 0:
        raise AssertionError(f"[{ver}] run-guest exited with status {proc.returncode}")
    if f"[W2-ALL-PASS] OpenBSD {ver}" not in proc.stdout:
        raise AssertionError(f"[{ver}] missing [W2-ALL-PASS] marker in guest output")
    if "[W2-FAIL]" in proc.stdout:
        raise AssertionError(f"[{ver}] guest reported failure marker")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--openbsd-version",
        default=os.environ.get("OPENBSD_VERSION", "all"),
        help="OpenBSD release(s) from config/versions/index.tsv: comma/space separated, or all",
    )
    ap.add_argument("--libobsdcompat-root", default="")
    ap.add_argument("--ports-lane-dir", default="")
    args = ap.parse_args()

    obsd_root = resolve_obsd_root(args.libobsdcompat_root)
    target = args.openbsd_version.strip()
    versions: List[str] = obsd_versions.resolve_versions(target)

    for ver in versions:
        t0 = time.monotonic()
        lane_dir = (
            pathlib.Path(args.ports_lane_dir).resolve()
            if args.ports_lane_dir
            else (REPO_ROOT / "build/openbsd" / ver / "emulate/emscripten").resolve()
        )
        print(f"\n=== [wave2_search_gnu] Verifying OpenBSD {ver} ({lane_dir}) ===")
        verify_packaged_artifacts(ver, lane_dir)
        verify_static_libs_sdk_link(ver, obsd_root, lane_dir)
        run_guest_suite(ver, obsd_root, lane_dir)
        dt = time.monotonic() - t0
        print(f"=== [wave2_search_gnu] OpenBSD {ver} PASSED 100% ({dt:.1f}s) ===")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
