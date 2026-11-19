#!/usr/bin/env python3
"""
tests/wave2_net_arch.py -- Comprehensive Dual-Release (OpenBSD 7.8 + 7.9)
WASM64 Verification Suite for Wave-2 Slice C (11 Networking, Web, Sync &
Archiver Ports):
  1. net/wget          (/usr/local/bin/wget + /usr/local/etc/wgetrc CA config)
  2. net/rsync         (/usr/local/bin/rsync: zstd, lz4, xxh3, iconv)
  3. net/socat         (/usr/local/bin/{socat,procan,filan})
  4. net/iperf3        (/usr/local/bin/iperf3 + libiperf.a: 3.18 on 7.8, 3.20 on 7.9)
  5. www/links         (/usr/local/bin/links: LibreSSL SNI + /etc/ssl/cert.pem)
  6. archivers/zip     (/usr/local/bin/{zip,zipcloak,zipnote,zipsplit})
  7. archivers/unzip   (/usr/local/bin/{unzip,zipinfo,funzip,unzipsfx} w/ 27 CVE patches)
  8. archivers/pigz    (/usr/local/bin/{pigz,unpigz}: multi-threaded zlib)
  9. archivers/gtar    (/usr/local/bin/gtar)
 10. archivers/libarchive (/usr/local/bin/{bsdtar,bsdcpio,bsdcat,bsdunzip} + libarchive.a + libarchive.pc)
 11. archivers/p7zip   (/usr/local/bin/{7za,7z,7zr}: WASM64 C++ via obsd-c++)

Runnable standalone for OpenBSD 7.8, 7.9, or both (`--openbsd-version 7.8|7.9|all`).
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from typing import Dict, List, Optional, Set, Tuple

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

SLICE_C_APPLETS = [
    "/usr/local/bin/wget",
    "/usr/local/bin/rsync",
    "/usr/local/bin/socat",
    "/usr/local/bin/procan",
    "/usr/local/bin/filan",
    "/usr/local/bin/iperf3",
    "/usr/local/bin/links",
    "/usr/local/bin/zip",
    "/usr/local/bin/zipcloak",
    "/usr/local/bin/zipnote",
    "/usr/local/bin/zipsplit",
    "/usr/local/bin/unzip",
    "/usr/local/bin/zipinfo",
    "/usr/local/bin/funzip",
    "/usr/local/bin/unzipsfx",
    "/usr/local/bin/pigz",
    "/usr/local/bin/unpigz",
    "/usr/local/bin/gtar",
    "/usr/local/bin/bsdtar",
    "/usr/local/bin/bsdcpio",
    "/usr/local/bin/bsdcat",
    "/usr/local/bin/bsdunzip",
    "/usr/local/bin/7za",
    "/usr/local/bin/7z",
    "/usr/local/bin/7zr",
]

EXPECTED_PKGS_BY_VER: Dict[str, List[str]] = {
    "7.8": [
        "wget-1.25.0.tgz",
        "rsync-3.4.1.tgz",
        "socat-1.7.4.1.tgz",
        "iperf3-3.18.tgz",
        "links-1.03.tgz",
        "zip-3.0.tgz",
        "unzip-6.0.tgz",
        "pigz-2.8.tgz",
        "gtar-1.35.tgz",
        "libarchive-3.8.1.tgz",
        "p7zip-17.06.tgz",
    ],
    "7.9": [
        "wget-1.25.0.tgz",
        "rsync-3.4.1.tgz",
        "socat-1.7.4.1.tgz",
        "iperf3-3.20.tgz",
        "links-1.03.tgz",
        "zip-3.0.tgz",
        "unzip-6.0.tgz",
        "pigz-2.8.tgz",
        "gtar-1.35.tgz",
        "libarchive-3.8.7.tgz",
        "p7zip-17.06.tgz",
    ],
}

STATIC_LIB_PROBE_C = r"""
#include <archive.h>
#include <archive_entry.h>
#include <iperf_api.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    struct archive *a = archive_write_new();
    struct archive_entry *ae = archive_entry_new();
    struct iperf_test *ipt = iperf_new_test();
    if (!a || !ae || !ipt) {
        return 1;
    }
    const char *ver = archive_version_string();
    archive_entry_free(ae);
    archive_write_free(a);
    iperf_free_test(ipt);
    return (ver != NULL && strncmp(ver, "libarchive ", 11) == 0) ? 0 : 2;
}
"""


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


def parse_svfs_paths(svfs_gz: pathlib.Path) -> Set[str]:
    raw = gzip.decompress(svfs_gz.read_bytes())
    hdr = struct.Struct("<IHHI")
    ent = struct.Struct("<BBHIIIHHI")
    magic, ver, _flags, count = hdr.unpack_from(raw, 0)
    assert magic == 0x53564653 and ver == 1, f"bad SVFS header in {svfs_gz}"
    paths: Set[str] = set()
    off = hdr.size
    for _ in range(count):
        _et, _r0, _perm, p_off, p_len, _d_off, _r1, _r2, _d_len = ent.unpack_from(raw, off)
        off += ent.size
        rel = raw[p_off : p_off + p_len].decode("utf-8")
        paths.add("/" + rel)
    return paths


def verify_lane_artifacts_and_static_libs(ver: str, obsd_root: pathlib.Path, lane_dir: pathlib.Path) -> None:
    tsv_path = lane_dir / "ports-applets.tsv"
    assert tsv_path.is_file(), f"[{ver}] missing {tsv_path}"
    tsv_paths: Dict[str, Tuple[str, str]] = {}
    for ln in tsv_path.read_text(encoding="utf-8").splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        sym, gp, _entry, obj_rel = s.split("\t")
        tsv_paths[gp] = (sym, obj_rel)
        assert (lane_dir / obj_rel).is_file(), f"[{ver}] missing localized applet object {lane_dir / obj_rel}"

    for gp in SLICE_C_APPLETS:
        assert gp in tsv_paths, f"[{ver}] missing applet guest path {gp} in ports-applets.tsv"

    # Verify 7z -> 7za shares 1 closure, zipinfo -> unzip shares 1 closure, unpigz -> pigz shares 1 closure
    assert tsv_paths["/usr/local/bin/7z"] == tsv_paths["/usr/local/bin/7za"], "7z and 7za must share one closure"
    assert tsv_paths["/usr/local/bin/zipinfo"] == tsv_paths["/usr/local/bin/unzip"], "zipinfo and unzip must share one closure"
    assert tsv_paths["/usr/local/bin/unpigz"] == tsv_paths["/usr/local/bin/pigz"], "unpigz and pigz must share one closure"

    # Verify /usr/local/etc/wgetrc CA bundle configuration in sysroot AND ports.svfs.gz
    wgetrc = lane_dir / "sysroot/usr/local/etc/wgetrc"
    assert wgetrc.is_file(), f"[{ver}] missing staged {wgetrc}"
    wgetrc_txt = wgetrc.read_text(encoding="utf-8")
    assert "ca_certificate = /etc/ssl/cert.pem" in wgetrc_txt, f"[{ver}] wgetrc missing ca_certificate setting"

    svfs_gz = lane_dir / "ports.svfs.gz"
    assert svfs_gz.is_file(), f"[{ver}] missing {svfs_gz}"
    svfs_paths = parse_svfs_paths(svfs_gz)
    assert "/usr/local/etc/wgetrc" in svfs_paths, f"[{ver}] /usr/local/etc/wgetrc missing from ports.svfs.gz"
    for gp in SLICE_C_APPLETS:
        assert gp in svfs_paths, f"[{ver}] {gp} stub missing from ports.svfs.gz"

    # Verify static libraries, headers, pkg-config, and .tgz packages
    for rel in (
        "sysroot/usr/local/lib/libarchive.a",
        "sysroot/usr/local/lib/libiperf.a",
        "sysroot/usr/local/lib/pkgconfig/libarchive.pc",
        "sysroot/usr/local/include/archive.h",
        "sysroot/usr/local/include/archive_entry.h",
        "sysroot/usr/local/include/iperf_api.h",
    ):
        assert (lane_dir / rel).is_file(), f"[{ver}] missing {lane_dir / rel}"

    for pkg_fn in EXPECTED_PKGS_BY_VER[ver]:
        assert (lane_dir / "packages" / pkg_fn).is_file(), f"[{ver}] missing package {pkg_fn}"

    # Compile & link C probe against libarchive.a (via obsd-pkg-config) + libiperf.a
    obsd_cc = REPO_ROOT / "sdk/bin/obsd-cc"
    obsd_pc = REPO_ROOT / "sdk/bin/obsd-pkg-config"
    env = dict(os.environ)
    env["OPENBSD_VERSION"] = ver
    env["LIBOBSDCOMPAT_ROOT"] = str(obsd_root)
    env["OBSD_STAGE_DIR"] = str(lane_dir / "stage")

    pc_flags = subprocess.check_output(
        [str(obsd_pc), "--cflags", "--libs", "--static", "libarchive"],
        env=env,
        text=True,
    ).split()

    with tempfile.TemporaryDirectory(prefix=f"obsd-wave2-libprobe-{ver}-") as td:
        tp = pathlib.Path(td)
        src = tp / "probe.c"
        out = tp / "probe"
        src.write_text(STATIC_LIB_PROBE_C, encoding="utf-8")
        subprocess.run(
            [str(obsd_cc), str(src), *pc_flags, "-liperf", "-lm", "-lpthread", "-o", str(out)],
            env=env,
            check=True,
        )

    print(f"[WAVE2-NET-ARCH/{ver}] Packaging, SVFS, wgetrc, .tgz & libarchive.a/libiperf.a closure: PASS")


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError(f"expected {n} bytes, got {len(buf)}")
        buf.extend(chunk)
    return bytes(buf)


class EphemeralTcpRelayServer:
    """Line-framing bidirectional TCP server on 127.0.0.1 for testing `socat TCP4:127.0.0.1:<port>`."""

    def __init__(self) -> None:
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(8)
        self.port = self._srv.getsockname()[1]
        self._stop = False
        self._thr = threading.Thread(target=self._serve, daemon=True)
        self._thr.start()

    def _serve(self) -> None:
        self._srv.settimeout(0.2)
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    @staticmethod
    def _handle(conn: socket.socket) -> None:
        with conn:
            conn.settimeout(10.0)
            data = bytearray()
            while True:
                try:
                    chunk = conn.recv(65536)
                except OSError:
                    break
                if not chunk:
                    break
                data.extend(chunk)
                if b"\n" in chunk:
                    break
            # Echo exact bytes prefixed with deterministic header so guest verifies round-trip SHA256
            conn.sendall(b"TCP_OK:" + bytes(data))

    def close(self) -> None:
        self._stop = True
        try:
            self._srv.close()
        except OSError:
            pass


class EphemeralIperf3Server:
    """Minimal RFC-exact iperf3 TCP loopback server on 127.0.0.1 for `iperf3 -c 127.0.0.1` over SVNP/1."""

    COOKIE_SIZE = 37
    TEST_START = 1
    TEST_RUNNING = 2
    TEST_END = 4
    PARAM_EXCHANGE = 9
    CREATE_STREAMS = 10
    EXCHANGE_RESULTS = 13
    DISPLAY_RESULTS = 14
    IPERF_DONE = 16

    def __init__(self) -> None:
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(8)
        self.port = self._srv.getsockname()[1]
        self._stop = False
        self._thr = threading.Thread(target=self._serve, daemon=True)
        self._thr.start()

    def _serve(self) -> None:
        self._srv.settimeout(0.2)
        while not self._stop:
            try:
                ctrl, _ = self._srv.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            try:
                self._run_session(ctrl)
            except Exception:
                try:
                    ctrl.close()
                except OSError:
                    pass

    def _run_session(self, ctrl: socket.socket) -> None:
        with ctrl:
            ctrl.settimeout(30.0)
            ctrl.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            cookie = _recv_exact(ctrl, self.COOKIE_SIZE)

            # 1. PARAM_EXCHANGE
            ctrl.sendall(bytes([self.PARAM_EXCHANGE]))
            (plen,) = struct.unpack("!I", _recv_exact(ctrl, 4))
            params = json.loads(_recv_exact(ctrl, plen).decode("utf-8"))
            num_streams = int(params.get("parallel", 1) or 1)

            # 2. CREATE_STREAMS
            ctrl.sendall(bytes([self.CREATE_STREAMS]))
            streams: List[socket.socket] = []
            self._srv.settimeout(15.0)
            for _ in range(num_streams):
                ds, _ = self._srv.accept()
                ds.settimeout(30.0)
                scookie = _recv_exact(ds, self.COOKIE_SIZE)
                if scookie != cookie:
                    ds.close()
                    raise ValueError("iperf3 stream cookie mismatch")
                streams.append(ds)

            # 3. Drain TCP stream(s) concurrently while waiting for TEST_END on ctrl
            rx_counts = [0] * num_streams
            stop_rx = threading.Event()
            t0 = time.monotonic()

            def _drain_stream(idx: int, s: socket.socket) -> None:
                s.settimeout(0.2)
                while not stop_rx.is_set():
                    try:
                        buf = s.recv(65536)
                        if not buf:
                            break
                        rx_counts[idx] += len(buf)
                    except TimeoutError:
                        continue
                    except OSError:
                        break

            workers = [
                threading.Thread(target=_drain_stream, args=(i, s), daemon=True)
                for i, s in enumerate(streams)
            ]
            for w in workers:
                w.start()

            ctrl.sendall(bytes([self.TEST_START]))
            ctrl.sendall(bytes([self.TEST_RUNNING]))

            # Wait for client TEST_END (4)
            while True:
                st_b = _recv_exact(ctrl, 1)[0]
                if st_b == self.TEST_END:
                    break

            stop_rx.set()
            for s in streams:
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                s.close()
            for w in workers:
                w.join(timeout=2.0)
            elapsed = max(time.monotonic() - t0, 0.001)

            # 4. EXCHANGE_RESULTS
            ctrl.sendall(bytes([self.EXCHANGE_RESULTS]))
            (clen,) = struct.unpack("!I", _recv_exact(ctrl, 4))
            client_res = json.loads(_recv_exact(ctrl, clen).decode("utf-8"))
            c_streams = client_res.get("streams") or [{"id": 1, "bytes": sum(rx_counts)}]

            srv_streams = []
            for i, cs in enumerate(c_streams):
                sid = int(cs.get("id", i + 1))
                b_rx = rx_counts[i] if i < len(rx_counts) and rx_counts[i] > 0 else int(cs.get("bytes", 0))
                srv_streams.append(
                    {
                        "id": sid,
                        "bytes": b_rx,
                        "retransmits": -1,
                        "jitter": 0,
                        "errors": 0,
                        "omitted_errors": 0,
                        "packets": 0,
                        "omitted_packets": 0,
                        "start_time": 0.0,
                        "end_time": elapsed,
                    }
                )
            srv_json = json.dumps(
                {
                    "cpu_util_total": 0.5,
                    "cpu_util_user": 0.3,
                    "cpu_util_system": 0.2,
                    "sender_has_retransmits": -1,
                    "streams": srv_streams,
                }
            ).encode("utf-8")
            ctrl.sendall(struct.pack("!I", len(srv_json)) + srv_json)

            # 5. DISPLAY_RESULTS -> wait for IPERF_DONE
            ctrl.sendall(bytes([self.DISPLAY_RESULTS]))
            _ = _recv_exact(ctrl, 1)

    def close(self) -> None:
        self._stop = True
        try:
            self._srv.close()
        except OSError:
            pass


GUEST_SCRIPT_TEMPLATE = r"""
set -e

EXPECTED_REL="__OPENBSD_VERSION__"
EXPECTED_IPERF_VER="__EXPECTED_IPERF_VER__"
TCP_ECHO_PORT="__TCP_ECHO_PORT__"
IPERF_PORT="__IPERF_PORT__"

fail() {
    echo "[WAVE2-NET-ARCH-FAIL] $*"
    exit 1
}

pass() {
    echo "[WAVE2-NET-ARCH-PASS] $1: $2"
}

[ "$(uname -s)" = "OpenBSD" ] || fail "expected OpenBSD"
[ "$(uname -r)" = "$EXPECTED_REL" ] || fail "expected release $EXPECTED_REL, got $(uname -r)"

# Verify all 25 applet binaries resolve on PATH
for bin in wget rsync socat procan filan iperf3 links zip zipcloak zipnote zipsplit unzip zipinfo funzip unzipsfx pigz unpigz gtar bsdtar bsdcpio bsdcat bsdunzip 7za 7z 7zr; do
    resolved=$(command -v "$bin") || fail "command -v $bin failed"
    [ "$resolved" = "/usr/local/bin/$bin" ] || fail "expected /usr/local/bin/$bin, got $resolved"
done
pass "01_path_resolution" "OpenBSD $EXPECTED_REL verified; all 25 Slice-C binaries on PATH"

# Build deterministic multi-file test corpus with SHA256 baseline
rm -rf /tmp/w2_corpus
mkdir -p /tmp/w2_corpus/dir_a/nested /tmp/w2_corpus/dir_b
cat /etc/services /etc/protocols > /tmp/w2_corpus/dir_a/nested/netdb.bin
cat /etc/group /etc/hosts /etc/services > /tmp/w2_corpus/dir_b/combo.dat
printf 'OpenBSD %s WASM64 UTF-8 café naïve 日本語\n' "$EXPECTED_REL" > /tmp/w2_corpus/dir_a/utf8.txt
ln -s nested/netdb.bin /tmp/w2_corpus/dir_a/netdb.link

SHA_NETDB=$(/bin/sha256 -q /tmp/w2_corpus/dir_a/nested/netdb.bin)
SHA_COMBO=$(/bin/sha256 -q /tmp/w2_corpus/dir_b/combo.dat)
SHA_UTF8=$(/bin/sha256 -q /tmp/w2_corpus/dir_a/utf8.txt)

# 02. Live HTTPS `wget -qO- https://example.com` (zero extra flags -> /usr/local/etc/wgetrc!)
WGET_VER=$(MALLOC_OPTIONS=JJ wget --version | head -n 3)
echo "$WGET_VER" | grep -q "GNU Wget 1.25.0" || fail "unexpected wget version: $WGET_VER"
WGET_HTML=$(MALLOC_OPTIONS=JJ wget -qO- https://example.com)
echo "$WGET_HTML" | grep -q "Example Domain" || fail "wget https://example.com missing 'Example Domain'"
pass "02_wget_live_https" "MALLOC_OPTIONS=JJ wget -qO- https://example.com verified via /usr/local/etc/wgetrc"

# 03. Live HTTPS `links -dump https://example.com` (zero extra flags -> TLS SNI + /etc/ssl/cert.pem!)
LINKS_VER=$(MALLOC_OPTIONS=JJ links -version 2>&1 || true)
echo "$LINKS_VER" | grep -q "Links 1.03" || fail "unexpected links version: $LINKS_VER"
LINKS_DUMP=$(MALLOC_OPTIONS=JJ links -dump https://example.com)
echo "$LINKS_DUMP" | grep -q "documentation examples" || echo "$LINKS_DUMP" | grep -q "Example Domain" || fail "links -dump https://example.com missing expected text: $LINKS_DUMP"
pass "03_links_live_https" "MALLOC_OPTIONS=JJ links -dump https://example.com rendered cleanly over verified TLS"

# 04. Local directory sync via `rsync -avz` (+ zstd + lz4/xxh3 + --delete)
rm -rf /tmp/w2_rsync_zlib /tmp/w2_rsync_zstd /tmp/w2_rsync_lz4
MALLOC_OPTIONS=JJ rsync -avz /tmp/w2_corpus/ /tmp/w2_rsync_zlib/ >/dev/null
[ "$(/bin/sha256 -q /tmp/w2_rsync_zlib/dir_a/nested/netdb.bin)" = "$SHA_NETDB" ] || fail "rsync -avz netdb SHA256 mismatch"
[ "$(/bin/sha256 -q /tmp/w2_rsync_zlib/dir_b/combo.dat)" = "$SHA_COMBO" ] || fail "rsync -avz combo SHA256 mismatch"
[ "$(/bin/sha256 -q /tmp/w2_rsync_zlib/dir_a/utf8.txt)" = "$SHA_UTF8" ] || fail "rsync -avz utf8 SHA256 mismatch"
[ -L /tmp/w2_rsync_zlib/dir_a/netdb.link ] || fail "rsync -avz did not preserve symlink"

MALLOC_OPTIONS=JJ rsync -av --compress --compress-choice=zstd /tmp/w2_corpus/ /tmp/w2_rsync_zstd/ >/dev/null
[ "$(/bin/sha256 -q /tmp/w2_rsync_zstd/dir_b/combo.dat)" = "$SHA_COMBO" ] || fail "rsync zstd SHA256 mismatch"

MALLOC_OPTIONS=JJ rsync -av --compress --compress-choice=lz4 --checksum --checksum-choice=xxh3 /tmp/w2_corpus/ /tmp/w2_rsync_lz4/ >/dev/null
[ "$(/bin/sha256 -q /tmp/w2_rsync_lz4/dir_a/nested/netdb.bin)" = "$SHA_NETDB" ] || fail "rsync lz4+xxh3 SHA256 mismatch"

: > /tmp/w2_rsync_zlib/stale_extra_file
MALLOC_OPTIONS=JJ rsync -avz --delete /tmp/w2_corpus/ /tmp/w2_rsync_zlib/ >/dev/null
[ ! -e /tmp/w2_rsync_zlib/stale_extra_file ] || fail "rsync --delete did not remove stale file"
pass "04_rsync_sync" "MALLOC_OPTIONS=JJ rsync -avz + zstd + lz4/xxh3 + --delete byte-exact SHA256"

# 05. `socat` UNIX / TCP / pipe bidirectional relays + `filan` + `procan`
PROCAN_OUT=$(MALLOC_OPTIONS=JJ procan)
echo "$PROCAN_OUT" | grep -q "process id =" || fail "procan output missing process id"
FILAN_OUT=$(MALLOC_OPTIONS=JJ filan -s)
echo "$FILAN_OUT" | grep -q "0 " || fail "filan -s output unexpected: $FILAN_OUT"

# 5a. Pipe / EXEC bidirectional relay
PIPE_SHA=$(MALLOC_OPTIONS=JJ socat - EXEC:"cat" < /tmp/w2_corpus/dir_b/combo.dat | /bin/sha256 -q)
[ "$PIPE_SHA" = "$SHA_COMBO" ] || fail "socat pipe relay SHA256 mismatch: $PIPE_SHA != $SHA_COMBO"

# 5b. UNIX socket bidirectional relay
rm -f /tmp/w2_socat.sock
MALLOC_OPTIONS=JJ socat UNIX-LISTEN:/tmp/w2_socat.sock EXEC:"tr a-z A-Z" &
SC_PID=$!
sleep 1
UNIX_OUT=$(printf 'openbsd-socat-unix-%s\n' "$EXPECTED_REL" | MALLOC_OPTIONS=JJ socat - UNIX-CONNECT:/tmp/w2_socat.sock)
wait "$SC_PID"
[ "$UNIX_OUT" = "OPENBSD-SOCAT-UNIX-$EXPECTED_REL" ] || fail "socat UNIX relay mismatch: $UNIX_OUT"

# 5c. TCP4 loopback bidirectional relay over SVNP/1
TCP_OUT=$(printf 'socat-tcp-%s\n' "$EXPECTED_REL" | MALLOC_OPTIONS=JJ socat - "TCP4:127.0.0.1:$TCP_ECHO_PORT")
[ "$TCP_OUT" = "TCP_OK:socat-tcp-$EXPECTED_REL" ] || fail "socat TCP4 relay mismatch: $TCP_OUT"
pass "05_socat_filan_procan" "MALLOC_OPTIONS=JJ socat pipe + UNIX-LISTEN/CONNECT + TCP4 + filan + procan OK"

# 06. `iperf3 -v` + live TCP loopback transfer (`iperf3 -c 127.0.0.1`)
IPERF_VER=$(MALLOC_OPTIONS=JJ iperf3 -v 2>&1)
echo "$IPERF_VER" | grep -q "iperf $EXPECTED_IPERF_VER" || fail "expected iperf $EXPECTED_IPERF_VER, got: $IPERF_VER"
IPERF_JSON=$(MALLOC_OPTIONS=JJ iperf3 -c 127.0.0.1 -p "$IPERF_PORT" -n 262144 -J)
IPERF_CHECK=$(printf '%s\n' "$IPERF_JSON" | jq -r '"\(.end.sum_sent.bytes >= 262144):\(.end.sum_received.bytes >= 262144):\(.end.sum_sent.bits_per_second > 0)"')
[ "$IPERF_CHECK" = "true:true:true" ] || fail "iperf3 loopback JSON check failed: $IPERF_CHECK ($IPERF_JSON)"
pass "06_iperf3_loopback" "iperf $EXPECTED_IPERF_VER + live TCP loopback 256 KiB transfer verified via jq"

# 07. `zip` + `unzip` + `zipinfo` + `zipnote` + `funzip` SHA256 round-trip
rm -rf /tmp/w2_zip /tmp/w2_unz
mkdir -p /tmp/w2_zip /tmp/w2_unz
(cd /tmp/w2_corpus && MALLOC_OPTIONS=JJ zip -q -r /tmp/w2_zip/archive.zip dir_a/nested/netdb.bin dir_b/combo.dat dir_a/utf8.txt)
ZINFO=$(MALLOC_OPTIONS=JJ zipinfo -1 /tmp/w2_zip/archive.zip)
echo "$ZINFO" | grep -q "dir_a/nested/netdb.bin" || fail "zipinfo missing netdb.bin"
echo "$ZINFO" | grep -q "dir_b/combo.dat" || fail "zipinfo missing combo.dat"
MALLOC_OPTIONS=JJ zipnote /tmp/w2_zip/archive.zip | grep -q "dir_b/combo.dat" || fail "zipnote failed"
MALLOC_OPTIONS=JJ unzip -q /tmp/w2_zip/archive.zip -d /tmp/w2_unz
[ "$(/bin/sha256 -q /tmp/w2_unz/dir_a/nested/netdb.bin)" = "$SHA_NETDB" ] || fail "unzip netdb SHA256 mismatch"
[ "$(/bin/sha256 -q /tmp/w2_unz/dir_b/combo.dat)" = "$SHA_COMBO" ] || fail "unzip combo SHA256 mismatch"
[ "$(/bin/sha256 -q /tmp/w2_unz/dir_a/utf8.txt)" = "$SHA_UTF8" ] || fail "unzip utf8 SHA256 mismatch"

MALLOC_OPTIONS=JJ zip -q -j /tmp/w2_zip/single.zip /tmp/w2_corpus/dir_b/combo.dat
FUNZ_SHA=$(MALLOC_OPTIONS=JJ funzip /tmp/w2_zip/single.zip | /bin/sha256 -q)
[ "$FUNZ_SHA" = "$SHA_COMBO" ] || fail "funzip SHA256 mismatch: $FUNZ_SHA != $SHA_COMBO"
pass "07_zip_unzip_roundtrip" "MALLOC_OPTIONS=JJ zip + unzip + zipinfo + zipnote + funzip exact SHA256"

# 08. Repeated C++ `7z` (`7za`) and `7zr` runs in ONE guest under MALLOC_OPTIONS=JJ
rm -rf /tmp/w2_7z
mkdir -p /tmp/w2_7z
iter=1
while [ "$iter" -le 3 ]; do
    MALLOC_OPTIONS=JJ 7z a -y "/tmp/w2_7z/run_${iter}.7z" /tmp/w2_corpus/dir_a/nested/netdb.bin /tmp/w2_corpus/dir_b/combo.dat /tmp/w2_corpus/dir_a/utf8.txt >/dev/null
    LIST_7Z=$(MALLOC_OPTIONS=JJ 7z l "/tmp/w2_7z/run_${iter}.7z")
    echo "$LIST_7Z" | grep -q "netdb.bin" || fail "7z l iter $iter missing netdb.bin"
    echo "$LIST_7Z" | grep -q "combo.dat" || fail "7z l iter $iter missing combo.dat"
    mkdir -p "/tmp/w2_7z/ext_${iter}"
    MALLOC_OPTIONS=JJ 7z x -y "-o/tmp/w2_7z/ext_${iter}" "/tmp/w2_7z/run_${iter}.7z" >/dev/null
    [ "$(/bin/sha256 -q "/tmp/w2_7z/ext_${iter}/netdb.bin")" = "$SHA_NETDB" ] || fail "7z iter $iter netdb SHA256 mismatch"
    [ "$(/bin/sha256 -q "/tmp/w2_7z/ext_${iter}/combo.dat")" = "$SHA_COMBO" ] || fail "7z iter $iter combo SHA256 mismatch"
    [ "$(/bin/sha256 -q "/tmp/w2_7z/ext_${iter}/utf8.txt")" = "$SHA_UTF8" ] || fail "7z iter $iter utf8 SHA256 mismatch"
    iter=$((iter + 1))
done

MALLOC_OPTIONS=JJ 7za a -tzip -y /tmp/w2_7z/cross.zip /tmp/w2_corpus/dir_b/combo.dat >/dev/null
mkdir -p /tmp/w2_7z/ext_zip
MALLOC_OPTIONS=JJ 7z x -y -o/tmp/w2_7z/ext_zip /tmp/w2_7z/cross.zip >/dev/null
[ "$(/bin/sha256 -q /tmp/w2_7z/ext_zip/combo.dat)" = "$SHA_COMBO" ] || fail "7za -tzip SHA256 mismatch"

MALLOC_OPTIONS=JJ 7zr a -y /tmp/w2_7z/reduced.7z /tmp/w2_corpus/dir_a/nested/netdb.bin >/dev/null
MALLOC_OPTIONS=JJ 7zr l /tmp/w2_7z/reduced.7z | grep -q "netdb.bin" || fail "7zr l missing netdb.bin"
mkdir -p /tmp/w2_7z/ext_7zr
MALLOC_OPTIONS=JJ 7zr x -y -o/tmp/w2_7z/ext_7zr /tmp/w2_7z/reduced.7z >/dev/null
[ "$(/bin/sha256 -q /tmp/w2_7z/ext_7zr/netdb.bin)" = "$SHA_NETDB" ] || fail "7zr x SHA256 mismatch"
pass "08_p7zip_repeated_cxx_runs" "3x 7z + 7za -tzip + 7zr C++ create/list/extract in one guest exact SHA256"

# 09. `pigz` + `unpigz` multi-threaded create + list + extract SHA256 round-trip
rm -rf /tmp/w2_pigz
mkdir -p /tmp/w2_pigz
cp /tmp/w2_corpus/dir_b/combo.dat /tmp/w2_pigz/combo.dat
MALLOC_OPTIONS=JJ pigz -p 2 -9 -k /tmp/w2_pigz/combo.dat
[ -s /tmp/w2_pigz/combo.dat.gz ] || fail "pigz did not produce .gz"
MALLOC_OPTIONS=JJ pigz -l /tmp/w2_pigz/combo.dat.gz | grep -q "combo.dat" || fail "pigz -l missing filename"
rm -f /tmp/w2_pigz/combo.dat
MALLOC_OPTIONS=JJ unpigz /tmp/w2_pigz/combo.dat.gz
[ "$(/bin/sha256 -q /tmp/w2_pigz/combo.dat)" = "$SHA_COMBO" ] || fail "unpigz SHA256 mismatch"
PIGZ_PIPE_SHA=$(MALLOC_OPTIONS=JJ pigz -p 2 -c < /tmp/w2_corpus/dir_a/nested/netdb.bin | MALLOC_OPTIONS=JJ unpigz -c | /bin/sha256 -q)
[ "$PIGZ_PIPE_SHA" = "$SHA_NETDB" ] || fail "pigz|unpigz pipe SHA256 mismatch"
pass "09_pigz_unpigz_roundtrip" "MALLOC_OPTIONS=JJ pigz -p 2 + pigz -l + unpigz exact SHA256"

# 10. `gtar` create + list + extract round-trips (tar, bzip2, xz, zstd, pigz)
rm -rf /tmp/w2_gtar
mkdir -p /tmp/w2_gtar/ext_plain /tmp/w2_gtar/ext_xz /tmp/w2_gtar/ext_pigz
MALLOC_OPTIONS=JJ gtar -cf /tmp/w2_gtar/c.tar -C /tmp/w2_corpus dir_a dir_b
MALLOC_OPTIONS=JJ gtar -tf /tmp/w2_gtar/c.tar | grep -q "dir_a/nested/netdb.bin" || fail "gtar -tf missing netdb.bin"
MALLOC_OPTIONS=JJ gtar -xf /tmp/w2_gtar/c.tar -C /tmp/w2_gtar/ext_plain
[ "$(/bin/sha256 -q /tmp/w2_gtar/ext_plain/dir_a/nested/netdb.bin)" = "$SHA_NETDB" ] || fail "gtar plain netdb SHA256 mismatch"
[ "$(/bin/sha256 -q /tmp/w2_gtar/ext_plain/dir_b/combo.dat)" = "$SHA_COMBO" ] || fail "gtar plain combo SHA256 mismatch"

MALLOC_OPTIONS=JJ gtar -cJf /tmp/w2_gtar/c.tar.xz -C /tmp/w2_corpus dir_a dir_b
MALLOC_OPTIONS=JJ gtar -xJf /tmp/w2_gtar/c.tar.xz -C /tmp/w2_gtar/ext_xz
[ "$(/bin/sha256 -q /tmp/w2_gtar/ext_xz/dir_a/utf8.txt)" = "$SHA_UTF8" ] || fail "gtar -J utf8 SHA256 mismatch"

MALLOC_OPTIONS=JJ gtar -I pigz -cf /tmp/w2_gtar/c.tar.gz -C /tmp/w2_corpus dir_b
MALLOC_OPTIONS=JJ gtar -I unpigz -xf /tmp/w2_gtar/c.tar.gz -C /tmp/w2_gtar/ext_pigz
[ "$(/bin/sha256 -q /tmp/w2_gtar/ext_pigz/dir_b/combo.dat)" = "$SHA_COMBO" ] || fail "gtar -I pigz SHA256 mismatch"
pass "10_gtar_roundtrip" "MALLOC_OPTIONS=JJ gtar create/list/extract (.tar, .tar.xz, -I pigz .tar.gz) exact SHA256"

# 11. `libarchive` (`bsdtar`, `bsdcpio`, `bsdcat`, `bsdunzip`) SHA256 round-trips
rm -rf /tmp/w2_libarch
mkdir -p /tmp/w2_libarch/ext_zst /tmp/w2_libarch/ext_lz4 /tmp/w2_libarch/ext_cpio /tmp/w2_libarch/ext_unzip

MALLOC_OPTIONS=JJ bsdtar --zstd -cf /tmp/w2_libarch/a.tar.zst -C /tmp/w2_corpus dir_a dir_b
MALLOC_OPTIONS=JJ bsdtar -tf /tmp/w2_libarch/a.tar.zst | grep -q "dir_b/combo.dat" || fail "bsdtar -tf missing combo.dat"
MALLOC_OPTIONS=JJ bsdtar -xf /tmp/w2_libarch/a.tar.zst -C /tmp/w2_libarch/ext_zst
[ "$(/bin/sha256 -q /tmp/w2_libarch/ext_zst/dir_a/nested/netdb.bin)" = "$SHA_NETDB" ] || fail "bsdtar zstd netdb SHA256 mismatch"
[ "$(/bin/sha256 -q /tmp/w2_libarch/ext_zst/dir_b/combo.dat)" = "$SHA_COMBO" ] || fail "bsdtar zstd combo SHA256 mismatch"

MALLOC_OPTIONS=JJ bsdtar --lz4 -cf /tmp/w2_libarch/a.tar.lz4 -C /tmp/w2_corpus dir_b/combo.dat
BSDCAT_SHA=$(MALLOC_OPTIONS=JJ bsdcat /tmp/w2_libarch/a.tar.lz4 | MALLOC_OPTIONS=JJ bsdtar -xOf - dir_b/combo.dat | /bin/sha256 -q)
[ "$BSDCAT_SHA" = "$SHA_COMBO" ] || fail "bsdcat|bsdtar lz4 SHA256 mismatch"

(cd /tmp/w2_corpus && printf 'dir_a/nested/netdb.bin\ndir_b/combo.dat\ndir_a/utf8.txt\n' | MALLOC_OPTIONS=JJ bsdcpio -o --format newc --quiet > /tmp/w2_libarch/a.cpio)
MALLOC_OPTIONS=JJ bsdcpio -t --quiet < /tmp/w2_libarch/a.cpio | grep -q "dir_b/combo.dat" || fail "bsdcpio -t missing combo.dat"
(cd /tmp/w2_libarch/ext_cpio && MALLOC_OPTIONS=JJ bsdcpio -i -d --quiet < /tmp/w2_libarch/a.cpio)
[ "$(/bin/sha256 -q /tmp/w2_libarch/ext_cpio/dir_a/nested/netdb.bin)" = "$SHA_NETDB" ] || fail "bsdcpio netdb SHA256 mismatch"
[ "$(/bin/sha256 -q /tmp/w2_libarch/ext_cpio/dir_b/combo.dat)" = "$SHA_COMBO" ] || fail "bsdcpio combo SHA256 mismatch"

MALLOC_OPTIONS=JJ bsdunzip -l /tmp/w2_zip/archive.zip | grep -q "dir_b/combo.dat" || fail "bsdunzip -l missing combo.dat"
MALLOC_OPTIONS=JJ bsdunzip -q /tmp/w2_zip/archive.zip -d /tmp/w2_libarch/ext_unzip
[ "$(/bin/sha256 -q /tmp/w2_libarch/ext_unzip/dir_b/combo.dat)" = "$SHA_COMBO" ] || fail "bsdunzip extract SHA256 mismatch"
pass "11_libarchive_roundtrip" "MALLOC_OPTIONS=JJ bsdtar (zstd/lz4) + bsdcat + bsdcpio + bsdunzip exact SHA256"

echo "[WAVE2-NET-ARCH-ALL-OK] OpenBSD $EXPECTED_REL passed all 11 Slice-C port suites!"
"""


def run_guest_suite(ver: str, obsd_root: pathlib.Path, lane_dir: pathlib.Path, timeout_ms: int) -> None:
    expected_iperf = "3.18" if ver == "7.8" else "3.20"
    merge_py = REPO_ROOT / "targets/emulate/emscripten/merge_wasm_guest.py"

    echo_srv = EphemeralTcpRelayServer()
    iperf_srv = EphemeralIperf3Server()
    try:
        script_text = (
            GUEST_SCRIPT_TEMPLATE.replace("__OPENBSD_VERSION__", ver)
            .replace("__EXPECTED_IPERF_VER__", expected_iperf)
            .replace("__TCP_ECHO_PORT__", str(echo_srv.port))
            .replace("__IPERF_PORT__", str(iperf_srv.port))
        )
        with tempfile.NamedTemporaryFile("w", prefix=f"wave2-net-arch-{ver}-", suffix=".sh", delete=False, encoding="utf-8") as tf:
            tf.write(script_text)
            script_path = pathlib.Path(tf.name)

        try:
            proc = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(merge_py),
                    "run-guest",
                    "--libobsdcompat-root",
                    str(obsd_root),
                    "--openbsd-version",
                    ver,
                    "--ports-lane-dir",
                    str(lane_dir),
                    "--enable-network",
                    "--timeout-ms",
                    str(timeout_ms),
                    "--script-file",
                    str(script_path),
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
            raise AssertionError(f"[{ver}] wave2_net_arch guest suite exited with rc={proc.returncode}")
        if f"[WAVE2-NET-ARCH-ALL-OK] OpenBSD {ver}" not in proc.stdout:
            raise AssertionError(f"[{ver}] missing final [WAVE2-NET-ARCH-ALL-OK] marker in guest output")
    finally:
        echo_srv.close()
        iperf_srv.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--openbsd-version", default="all", choices=("7.8", "7.9", "all"))
    ap.add_argument("--libobsdcompat-root", default="")
    ap.add_argument("--ports-lane-dir", default="")
    ap.add_argument("--timeout-ms", type=int, default=240000)
    args = ap.parse_args()

    obsd_root = resolve_obsd_root(args.libobsdcompat_root)
    versions = ["7.8", "7.9"] if args.openbsd_version == "all" else [args.openbsd_version]

    for ver in versions:
        lane_dir = (
            pathlib.Path(args.ports_lane_dir).resolve()
            if args.ports_lane_dir
            else (REPO_ROOT / "build/openbsd" / ver / "emulate/emscripten")
        )
        verify_lane_artifacts_and_static_libs(ver, obsd_root, lane_dir)
        run_guest_suite(ver, obsd_root, lane_dir, args.timeout_ms)

    print(f"[WAVE2-NET-ARCH] ALL REQUESTED RELEASES ({', '.join(versions)}) PASSED 100%!")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
