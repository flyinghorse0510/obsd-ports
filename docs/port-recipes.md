# Declarative Port Recipe Contract (`ports/<portpath>/port.toml`)

Each ported package lives at `ports/<portpath>/port.toml` (supporting both 2-level paths like `ports/archivers/bzip2/port.toml` and 3-level paths like `ports/lang/lua/5.4/port.toml`).

A single `port.toml` builds against **both** OpenBSD `7.8` and OpenBSD `7.9` automatically: `tools/build_ports.py` reads the release-specific `distinfo`, `Makefile`, and `patches/patch-*` from `vendor/openbsd/versions/$(OPENBSD_VERSION)/ports/<vendor_port>/`.

## Schema Reference

```toml
# Optional: defaults to directory path relative to ports/
port = "textproc/jq"
vendor_port = "textproc/jq"

# Topological build dependencies (built & staged into stage/usr/local first)
depends = ["textproc/oniguruma"]

# "gnu" (./configure) | "simple" | "cmake" | "make" | "script"
build_style = "gnu"
separate_build = false
use_gmake = true

# Vendor patch application in work/<port>/ (never mutates vendor/)
apply_vendor_patches = true
skip_vendor_patches = []
patch_strip = 0

# Compiler/linker additions (SDK already injects -O2, OpenBSD sysroot, and stage /usr/local)
cflags = []
cppflags = []
ldflags = []
libs = []
env = {}

# Configure options (for build_style = "gnu" or "simple")
configure_script = "./configure"
configure_host = true          # passes --host=aarch64-unknown-openbsd<ver> --build=...
configure_default_args = true  # passes --prefix=/usr/local --sysconfdir=/etc --mandir=/usr/local/man --disable-shared --enable-static
configure_args = [
    "--with-oniguruma=/usr/local",
    "--disable-docs",
    "--disable-valgrind",
]

# Build & install overrides (for build_style = "make" or custom targets)
make_args = []
make_targets = []
install_target = "install"
install_use_destdir = true     # true -> DESTDIR=<stage>; false -> PREFIX=<stage>/usr/local
install_args = []

# Optional shell hooks (executed with bash -euo pipefail in WRKBUILD;
# $WRKSRC, $WRKBUILD, $STAGE_DIR, $PORT_DIR, $VENDOR_PORT_DIR, $PREFIX, $CC, $AR, $JOBS exported)
pre_configure = []
post_configure = []
pre_build = []
build_cmd = []
install_cmd = []
post_install = []

# Localized WASM64 applet exports (omit or leave empty for pure library ports like oniguruma)
[[applets]]
sym = "jq"
binary = "/usr/local/bin/jq"
paths = ["/usr/local/bin/jq"]
entry = "auto"                 # auto-detects __main_argc_argv, main, or obsd_tool_main

# Optional per-release overrides if 7.8 and 7.9 ever need distinct flags:
# [versions."7.8"]
# skip_vendor_patches = ["patch-foo"]
```

## Multi-Call Alias Example (`archivers/xz`)

```toml
[[applets]]
sym = "xz"
binary = "/usr/local/bin/xz"
paths = [
    "/usr/local/bin/xz",
    "/usr/local/bin/unxz",
    "/usr/local/bin/xzcat",
    "/usr/local/bin/lzma",
    "/usr/local/bin/unlzma",
    "/usr/local/bin/lzcat",
]
```

## Optional Port-Local Files

- `ports/<portpath>/patches/patch-*` — Applied after `vendor/.../patches/patch-*` inside `work/`.
- `ports/<portpath>/build.sh` — Executed when `build_style = "script"`.
