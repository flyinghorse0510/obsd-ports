#!/usr/bin/env bash
set -euo pipefail

case "$OPENBSD_VERSION" in
  7.8)
    PY_VER="3.12"
    FULL_VER="3.12.11"
    ;;
  7.9)
    PY_VER="3.13"
    FULL_VER="3.13.13"
    ;;
  8.0)
    PY_VER="3.14"
    FULL_VER="3.14.7"
    ;;
  *)
    echo "Unsupported OPENBSD_VERSION=$OPENBSD_VERSION for lang/python/3" >&2
    exit 1
    ;;
esac

CACHE_SDK="$OBSD_PORTS_ROOT/.cache/sdk"
DISTFILES_DIR="$OBSD_PORTS_ROOT/.cache/distfiles"
mkdir -p "$CACHE_SDK"

# 1. Resolve or build/cache matching minor-version native Linux host python for --with-build-python
BUILD_PYTHON=""
if command -v /usr/bin/python3 >/dev/null 2>&1; then
  HOST_SYS_VER=$(/usr/bin/python3 -I -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || true)
  if [ "$HOST_SYS_VER" = "$PY_VER" ]; then
    BUILD_PYTHON="/usr/bin/python3"
  fi
fi

if [ -z "$BUILD_PYTHON" ]; then
  HOST_PY_PREFIX="$CACHE_SDK/host-python-$PY_VER"
  CAND_PY="$HOST_PY_PREFIX/bin/python$PY_VER"
  LOCK_FILE="$CACHE_SDK/host-python-$PY_VER.lock"
  (
    flock -x 9
    if [ ! -x "$CAND_PY" ] || ! "$CAND_PY" -I -c "import sys, encodings; assert f'{sys.version_info.major}.{sys.version_info.minor}' == '$PY_VER'" >/dev/null 2>&1; then
      echo "  [host-python] building native bootstrap python$PY_VER ($FULL_VER) -> $HOST_PY_PREFIX..."
      TMP_HOST_DIR=$(mktemp -d "${TMPDIR:-/tmp}/obsd-host-py${PY_VER}-XXXXXX")
      rm -rf "$HOST_PY_PREFIX"
      tar -xzf "$DISTFILES_DIR/Python-$FULL_VER.tgz" -C "$TMP_HOST_DIR"
      mkdir -p "$TMP_HOST_DIR/build"
      (
        cd "$TMP_HOST_DIR/build"
        env -i HOME="${HOME:-/tmp}" PATH="/usr/bin:/bin" CC="${HOSTCC:-cc}" CFLAGS="-O1" \
          "$TMP_HOST_DIR/Python-$FULL_VER/configure" \
          --prefix="$HOST_PY_PREFIX" \
          --with-ensurepip=no \
          --disable-test-modules \
          --without-doc-strings
        env -i HOME="${HOME:-/tmp}" PATH="/usr/bin:/bin" \
          make -j"$JOBS"
        env -i HOME="${HOME:-/tmp}" PATH="/usr/bin:/bin" \
          make install
      )
      rm -rf "$TMP_HOST_DIR"
    fi
  ) 9>"$LOCK_FILE"
  BUILD_PYTHON="$CAND_PY"
fi

echo "  [python3] using --with-build-python=$BUILD_PYTHON"

# 2. Prepare $WRKSRC for static OpenBSD WASM64 cross-compilation
rm -rf "$WRKSRC/Modules/expat"

# Teach pre-generated configure about cross-compiling to OpenBSD (ac_sys_system=OpenBSD,
# ac_sys_release=$OPENBSD_VERSION -> MACHDEP=openbsd8/openbsd7) and MULTIARCH=""
python3 -I - "$WRKSRC/configure" "$OPENBSD_VERSION" <<'PY'
import pathlib, sys
cfg_p = pathlib.Path(sys.argv[1])
obsd_ver = sys.argv[2]
txt = cfg_p.read_text(encoding="utf-8")

old_cross1 = '\t*)\n\t\t# for now, limit cross builds to known configurations\n\t\tMACHDEP="unknown"\n\t\tas_fn_error $? "cross build not supported for $host" "$LINENO" 5\n\tesac\n\tac_sys_release='
new_cross1 = (
    f'\t*-*-openbsd*)\n\t\tac_sys_system=OpenBSD\n\t\tac_sys_release="{obsd_ver}"\n\t\t;;\n'
    '\t*)\n\t\t# for now, limit cross builds to known configurations\n\t\tMACHDEP="unknown"\n\t\tas_fn_error $? "cross build not supported for $host" "$LINENO" 5\n\tesac\n\tac_sys_release=${ac_sys_release:-}'
)
if old_cross1 not in txt:
    raise SystemExit("FATAL: could not find cross-build MACHDEP case in configure")
txt = txt.replace(old_cross1, new_cross1, 1)

old_cross2 = '\twasm32-*-* | wasm64-*-*)\n'
new_cross2 = (
    '\t*-*-openbsd*)\n\t\t_host_cpu=wasm64\n\t\t_host_ident=wasm64\n\t\t;;\n'
    '\twasm32-*-* | wasm64-*-*)\n'
)
if old_cross2 not in txt:
    raise SystemExit("FATAL: could not find cross-build _PYTHON_HOST_PLATFORM case in configure")
txt = txt.replace(old_cross2, new_cross2, 1)

txt = txt.replace('  FreeBSD*) :\n    MULTIARCH="" ;;', '  FreeBSD*|OpenBSD*) :\n    MULTIARCH="" ;;')
cfg_p.write_text(txt, encoding="utf-8")
PY

# OpenBSD libedit's readline/readline.h declares rl_free_line_state() without defining it in libedit
python3 -I - "$WRKSRC/Modules/readline.c" <<'PY'
import pathlib, sys
rl_p = pathlib.Path(sys.argv[1])
rl_txt = rl_p.read_text(encoding="utf-8")
old_call = "                rl_free_line_state();"
new_call = "#ifndef __OpenBSD__\n                rl_free_line_state();\n#endif"
if old_call not in rl_txt:
    raise SystemExit("FATAL: expected rl_free_line_state() in Modules/readline.c")
rl_p.write_text(rl_txt.replace(old_call, new_call, 1), encoding="utf-8")
PY

# Prevent make from trying to regenerate configure/pyconfig.h.in after vendor patch-configure_ac
touch "$WRKSRC/configure" "$WRKSRC/pyconfig.h.in"

HOST_ARCH=$(uname -m || echo x86_64)
OBS_INC="$LIBOBSDCOMPAT_ROOT/build/wasm-$OPENBSD_VERSION/include-root-$OPENBSD_VERSION"

export MODULE_BUILDTYPE="static"
export ac_cv_file__dev_ptmx="no"
export ac_cv_file__dev_ptc="no"
export ac_cv_working_openssl_hashlib="yes"
export ac_cv_working_openssl_ssl="yes"
export ac_cv_buggy_getaddrinfo="no"
export ac_cv_working_tzset="yes"
export ac_cv_have_long_long_format="yes"
export ac_cv_pthread_is_default="yes"
export ac_cv_kpthread="no"
export ac_cv_pthread="yes"
export ac_cv_BrokenPipeError="no"

# Disable modules requiring absent/dynamic-only libs so 100% of extensions link statically
export py_cv_module__ctypes="n/a"
export py_cv_module__ctypes_test="n/a"
export py_cv_module__tkinter="n/a"
export py_cv_module__curses_panel="n/a"
export py_cv_module__gdbm="n/a"
export py_cv_module__dbm="n/a"
export py_cv_module_nis="n/a"
export py_cv_module_ossaudiodev="n/a"
export py_cv_module_spwd="n/a"
export py_cv_module__uuid="n/a"
export py_cv_module__zstd="n/a"
export py_cv_module__scproxy="n/a"
export py_cv_module_xxlimited="n/a"
export py_cv_module_xxlimited_35="n/a"
export py_cv_module__testimportmultiple="n/a"
export py_cv_module__testmultiphase="n/a"
export py_cv_module__testsinglephase="n/a"

export OPENSSL_INCLUDES="-I$OBS_INC"
export OPENSSL_LDFLAGS=""
export OPENSSL_LIBS="-lssl -lcrypto"
export LIBCRYPTO_LIBS="-lcrypto"
export ZLIB_CFLAGS="-I$OBS_INC"
export ZLIB_LIBS="-lz"
export BZIP2_CFLAGS="-I$STAGE_DIR/usr/local/include"
export BZIP2_LIBS="-L$STAGE_DIR/usr/local/lib -lbz2"
export LIBLZMA_CFLAGS="-I$STAGE_DIR/usr/local/include"
export LIBLZMA_LIBS="-L$STAGE_DIR/usr/local/lib -llzma"
export LIBSQLITE3_CFLAGS="-I$STAGE_DIR/usr/local/include"
export LIBSQLITE3_LIBS="-L$STAGE_DIR/usr/local/lib -lsqlite3"
export LIBEXPAT_CFLAGS="-DXML_DTD -DXML_GE=1 -I$OBS_INC"
export LIBEXPAT_LDFLAGS="-lexpat"
export CURSES_CFLAGS="-D_XOPEN_SOURCE_EXTENDED -DNCURSES_WIDECHAR=1 -I$OBS_INC"
export CURSES_LIBS="-lncursesw"
export READLINE_CFLAGS="-I$OBS_INC"
export READLINE_LIBS="-lreadline -lncursesw"

export CFLAGS="-O2 -DXML_DTD -DXML_GE=1 -D_XOPEN_SOURCE_EXTENDED -DNCURSES_WIDECHAR=1"
export CPPFLAGS="-I$STAGE_DIR/usr/local/include -DXML_DTD -DXML_GE=1 -D_XOPEN_SOURCE_EXTENDED -DNCURSES_WIDECHAR=1"
export LDFLAGS="-L$STAGE_DIR/usr/local/lib"
export LIBS="-liconv -lutil -lpthread -lm"

mkdir -p "$WRKBUILD/Modules"
cat > "$WRKBUILD/Modules/Setup.local" <<'EOF'
*static*
EOF

# 3. Configure CPython
cd "$WRKBUILD"
sh "$WRKSRC/configure" \
  --host="aarch64-unknown-openbsd${OPENBSD_VERSION}" \
  --build="${HOST_ARCH}-unknown-linux-gnu" \
  --prefix="/usr/local" \
  --sysconfdir="/etc" \
  --mandir="/usr/local/man" \
  --with-build-python="$BUILD_PYTHON" \
  --disable-shared \
  --without-pymalloc \
  --with-system-expat \
  --with-ensurepip=no \
  --enable-ipv6 \
  --disable-test-modules \
  --without-lto \
  MODULE_BUILDTYPE=static

# Ensure Setup.stdlib has zero *shared* modules enabled
python3 -I - "$WRKBUILD/Modules/Setup.stdlib" "$WRKBUILD/Modules/Setup.local" <<'PY'
import pathlib, sys
stdlib_p = pathlib.Path(sys.argv[1])
local_p = pathlib.Path(sys.argv[2])
lines = stdlib_p.read_text(encoding="utf-8").splitlines()
out = []
in_shared = False
for ln in lines:
    s = ln.strip()
    if s == "*shared*":
        in_shared = True
        out.append("# *shared* disabled for static WASM64 build")
        continue
    if in_shared and s and not s.startswith("#"):
        out.append("# " + ln)
    else:
        out.append(ln)
stdlib_p.write_text("\n".join(out) + "\n", encoding="utf-8")
local_p.write_text("*static*\n", encoding="utf-8")
PY

gmake -C "$WRKBUILD" Makefile

# Verify every required static C extension is wired into Modules/config.c
python3 -I - "$WRKBUILD/Modules/config.c" <<'PY'
import pathlib, sys
cfg_c = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
required = [
    "_ssl", "_hashlib", "zlib", "pyexpat", "_elementtree",
    "_sqlite3", "_bz2", "_lzma", "select", "fcntl", "termios",
    "_posixsubprocess", "_socket", "math", "_json", "_struct",
    "binascii", "unicodedata", "array", "_random", "_datetime",
    "_bisect", "_heapq", "_csv", "_pickle", "readline", "_curses",
    "_asyncio", "_md5", "_sha1", "_sha2", "_sha3", "_blake2",
]
missing = [m for m in required if f'"{m}"' not in cfg_c]
if missing:
    sys.stderr.write(f"FATAL: missing static CPython stdlib modules in Modules/config.c: {missing}\n")
    raise SystemExit(1)
print(f"  [python3] verified all {len(required)} required static C modules in Modules/config.c!")
PY

# 4. Build & stage CPython
gmake -C "$WRKBUILD" -j"$JOBS"
gmake -C "$WRKBUILD" install DESTDIR="$STAGE_DIR" RANLIB=:

# Ensure /usr/local/bin/{python3.<minor>,python3,python} exist cleanly
ln -sf "python$PY_VER" "$STAGE_DIR/usr/local/bin/python3"
ln -sf "python$PY_VER" "$STAGE_DIR/usr/local/bin/python"

# Fix pydoc3 shebang and remove unneeded helper scripts
rm -f "$STAGE_DIR/usr/local/bin/idle3"* \
      "$STAGE_DIR/usr/local/bin/2to3"* \
      "$STAGE_DIR/usr/local/bin/python3"*-config \
      "$STAGE_DIR/usr/local/bin/pip"*
for sc in "$STAGE_DIR/usr/local/bin/pydoc"*; do
  if [ -f "$sc" ] && [ ! -L "$sc" ]; then
    sed -i "1s|^#!.*|#!/usr/local/bin/python$PY_VER|" "$sc"
    chmod 0755 "$sc"
  fi
done

# Install OpenBSD PSF license change summary
if [ -f "$VENDOR_PORT_DIR/files/CHANGES.OpenBSD" ]; then
  obsd-install -d -m 0755 "$STAGE_DIR/usr/local/share/doc/python$PY_VER"
  obsd-install -c -m 0644 "$VENDOR_PORT_DIR/files/CHANGES.OpenBSD" \
    "$STAGE_DIR/usr/local/share/doc/python$PY_VER/CHANGES.OpenBSD"
fi

# 5. Stdlib size hygiene: prune unused test/GUI dirs, static archives, and __pycache__/*.pyc
PYLIB="$STAGE_DIR/usr/local/lib/python$PY_VER"
mkdir -p "$PYLIB/site-packages"

rm -rf "$PYLIB/test" \
       "$PYLIB/tests" \
       "$PYLIB/idlelib" \
       "$PYLIB/tkinter" \
       "$PYLIB/turtledemo" \
       "$PYLIB/ensurepip" \
       "$PYLIB/pydoc_data" \
       "$PYLIB/lib2to3" \
       "$PYLIB/ctypes/test" \
       "$PYLIB/unittest/test" \
       "$PYLIB/config-${PY_VER}"* \
       "$STAGE_DIR/usr/local/lib/libpython"* \
       "$STAGE_DIR/usr/local/lib/pkgconfig/python"*

find "$PYLIB" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "$PYLIB" -type f \( -name "*.pyc" -o -name "*.pyo" -o -name "*.a" \) -delete 2>/dev/null || true
