/*
 * ports_pty_probe.c -- OpenBSD WASM64 Guest PTY Curses & Static Library Probe
 *
 * Compiled with `sdk/bin/obsd-cc` against staged `/usr/local/{include,lib}` and
 * OpenBSD base `libc`/`libutil`/`libcurses`/`libz`/`libssl`/`libcrypto`:
 *   1. Verifies C API execution of staged static libraries (`libbz2.a`,
 *      `liblzma.a`, `libzstd.a`, `libonig.a`, `libsqlite3.a`, `liblua5.4.a`,
 *      `libcurl.a`).
 *   2. Exercises `/usr/local/bin/nano` inside a genuine OpenBSD 80x24 PTY
 *      (`openpty(3)` + `TIOCSWINSZ`), verifying curses escape sequence rendering,
 *      UTF-8 text entry, save (`^O`), and clean exit (`^X`).
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <util.h>

#include <bzlib.h>
#include <lzma.h>
#include <zstd.h>
#include <oniguruma.h>
#include <sqlite3.h>
#include <lua-5.4/lua.h>
#include <lua-5.4/lauxlib.h>
#include <lua-5.4/lualib.h>
#include <curl/curl.h>
#include <iconv.h>
#include <localcharset.h>
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <pcre.h>
#include <lz4.h>
#include <xxhash.h>
#include <png.h>

static int
verify_static_libraries(void)
{
	/* 1. libbz2.a */
	const char *bz_ver = BZ2_bzlibVersion();
	if (bz_ver == NULL || bz_ver[0] == '\0') {
		fprintf(stderr, "[FAIL] BZ2_bzlibVersion returned empty\n");
		return 1;
	}

	/* 2. liblzma.a */
	const char *xz_ver = lzma_version_string();
	if (xz_ver == NULL || xz_ver[0] == '\0') {
		fprintf(stderr, "[FAIL] lzma_version_string returned empty\n");
		return 1;
	}

	/* 3. libzstd.a */
	unsigned zstd_ver = ZSTD_versionNumber();
	if (zstd_ver < 10500) {
		fprintf(stderr, "[FAIL] unexpected ZSTD_versionNumber: %u\n", zstd_ver);
		return 1;
	}

	/* 4. libonig.a */
	if (onig_init() != 0) {
		fprintf(stderr, "[FAIL] onig_init failed\n");
		return 1;
	}
	regex_t *reg = NULL;
	OnigErrorInfo einfo;
	const UChar *pat = (const UChar *)"^OpenBSD-([0-9]+\\.[0-9]+)$";
	const UChar *str = (const UChar *)"OpenBSD-7.9";
	if (onig_new(&reg, pat, pat + strlen((const char *)pat),
	    ONIG_OPTION_DEFAULT, ONIG_ENCODING_UTF8, ONIG_SYNTAX_DEFAULT, &einfo) != ONIG_NORMAL) {
		fprintf(stderr, "[FAIL] onig_new failed\n");
		return 1;
	}
	OnigRegion *region = onig_region_new();
	int r = onig_search(reg, str, str + strlen((const char *)str),
	    str, str + strlen((const char *)str), region, ONIG_OPTION_NONE);
	onig_region_free(region, 1);
	onig_free(reg);
	if (r < 0) {
		fprintf(stderr, "[FAIL] onig_search did not match\n");
		return 1;
	}

	/* 5. libsqlite3.a */
	sqlite3 *db = NULL;
	if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
		fprintf(stderr, "[FAIL] sqlite3_open(:memory:) failed\n");
		return 1;
	}
	sqlite3_stmt *stmt = NULL;
	if (sqlite3_prepare_v2(db, "SELECT 6 * 7;", -1, &stmt, NULL) != SQLITE_OK ||
	    sqlite3_step(stmt) != SQLITE_ROW ||
	    sqlite3_column_int(stmt, 0) != 42) {
		fprintf(stderr, "[FAIL] sqlite3 C API query failed\n");
		sqlite3_close(db);
		return 1;
	}
	sqlite3_finalize(stmt);
	sqlite3_close(db);

	/* 6. liblua5.4.a */
	lua_State *L = luaL_newstate();
	if (L == NULL) {
		fprintf(stderr, "[FAIL] luaL_newstate failed\n");
		return 1;
	}
	luaL_openlibs(L);
	if (luaL_dostring(L, "return 13 * 3 + 3") != LUA_OK ||
	    lua_tointeger(L, -1) != 42) {
		fprintf(stderr, "[FAIL] luaL_dostring failed\n");
		lua_close(L);
		return 1;
	}
	lua_close(L);

	/* 7. libcurl.a */
	curl_version_info_data *cv = curl_version_info(CURLVERSION_NOW);
	if (cv == NULL || cv->ssl_version == NULL ||
	    strstr(cv->ssl_version, "LibreSSL") == NULL) {
		fprintf(stderr, "[FAIL] libcurl ssl_version missing LibreSSL (got: %s)\n",
		    cv && cv->ssl_version ? cv->ssl_version : "NULL");
		return 1;
	}

	/* 8. libiconv.a + libcharset.a */
	const char *cs = locale_charset();
	if (cs == NULL || cs[0] == '\0') {
		fprintf(stderr, "[FAIL] locale_charset returned empty\n");
		return 1;
	}
	iconv_t cd = iconv_open("UTF-16LE", "UTF-8");
	if (cd == (iconv_t)-1) {
		fprintf(stderr, "[FAIL] iconv_open failed\n");
		return 1;
	}
	char ic_in_buf[] = "BSD";
	char *ic_in = ic_in_buf;
	size_t ic_in_left = 3;
	char ic_out_buf[16] = {0};
	char *ic_out = ic_out_buf;
	size_t ic_out_left = sizeof(ic_out_buf);
	if (iconv(cd, &ic_in, &ic_in_left, &ic_out, &ic_out_left) == (size_t)-1 ||
	    ic_in_left != 0 || (sizeof(ic_out_buf) - ic_out_left) != 6) {
		fprintf(stderr, "[FAIL] iconv UTF-8->UTF-16LE conversion failed\n");
		iconv_close(cd);
		return 1;
	}
	iconv_close(cd);

	/* 9. libpcre2-8.a */
	int p2_err = 0;
	PCRE2_SIZE p2_off = 0;
	pcre2_code *p2_re = pcre2_compile((PCRE2_SPTR)"^WASM([0-9]+)$",
	    PCRE2_ZERO_TERMINATED, 0, &p2_err, &p2_off, NULL);
	if (p2_re == NULL) {
		fprintf(stderr, "[FAIL] pcre2_compile failed\n");
		return 1;
	}
	pcre2_match_data *p2_md = pcre2_match_data_create_from_pattern(p2_re, NULL);
	int p2_rc = pcre2_match(p2_re, (PCRE2_SPTR)"WASM64", 6, 0, 0, p2_md, NULL);
	pcre2_match_data_free(p2_md);
	pcre2_code_free(p2_re);
	if (p2_rc < 2) {
		fprintf(stderr, "[FAIL] pcre2_match failed: %d\n", p2_rc);
		return 1;
	}

	/* 10. libpcre.a */
	const char *p1_err = NULL;
	int p1_off = 0;
	pcre *p1_re = pcre_compile("^OpenBSD-([0-9]+)$", 0, &p1_err, &p1_off, NULL);
	if (p1_re == NULL) {
		fprintf(stderr, "[FAIL] pcre_compile failed\n");
		return 1;
	}
	int p1_ov[6];
	int p1_rc = pcre_exec(p1_re, NULL, "OpenBSD-79", 10, 0, 0, p1_ov, 6);
	pcre_free(p1_re);
	if (p1_rc < 2) {
		fprintf(stderr, "[FAIL] pcre_exec failed: %d\n", p1_rc);
		return 1;
	}

	/* 11. liblz4.a */
	const char lz4_src[] = "OpenBSD WASM64 LZ4 static library roundtrip payload OpenBSD WASM64";
	char lz4_cmp[128];
	char lz4_dec[128];
	int lz4_clen = LZ4_compress_default(lz4_src, lz4_cmp, (int)sizeof(lz4_src), (int)sizeof(lz4_cmp));
	int lz4_dlen = (lz4_clen > 0) ? LZ4_decompress_safe(lz4_cmp, lz4_dec, lz4_clen, (int)sizeof(lz4_dec)) : -1;
	if (lz4_dlen != (int)sizeof(lz4_src) || memcmp(lz4_src, lz4_dec, sizeof(lz4_src)) != 0) {
		fprintf(stderr, "[FAIL] liblz4 round-trip failed\n");
		return 1;
	}

	/* 12. libxxhash.a */
	XXH64_hash_t xh = XXH64("OpenBSD", 7, 0);
	if (xh == 0) {
		fprintf(stderr, "[FAIL] XXH64 returned 0\n");
		return 1;
	}

	/* 13. libpng.a */
	png_uint_32 png_ver = png_access_version_number();
	if (png_ver < 10600) {
		fprintf(stderr, "[FAIL] unexpected png_access_version_number: %lu\n", (unsigned long)png_ver);
		return 1;
	}

	printf("[PORTS-PASS] static_libs_c_api: bzip2=%s lzma=%s zstd=%u sqlite=%s lua=%s curl=%s(%s) lz4=%d xxh=%u png=%lu\n",
	    bz_ver, xz_ver, zstd_ver, sqlite3_libversion(), LUA_RELEASE,
	    cv->version, cv->ssl_version, LZ4_versionNumber(), XXH_versionNumber(), (unsigned long)png_ver);
	fflush(stdout);
	return 0;
}

static void
drain_pty(int master_fd, char *acc, size_t cap, size_t *len_inout, int wait_ms)
{
	struct pollfd pfd;
	pfd.fd = master_fd;
	pfd.events = POLLIN;

	int elapsed = 0;
	while (elapsed < wait_ms) {
		int prc = poll(&pfd, 1, 25);
		if (prc > 0 && (pfd.revents & POLLIN)) {
			char buf[1024];
			ssize_t n = read(master_fd, buf, sizeof(buf));
			if (n > 0) {
				size_t space = (*len_inout + 1 < cap) ? (cap - 1 - *len_inout) : 0;
				size_t copy = ((size_t)n < space) ? (size_t)n : space;
				if (copy > 0) {
					memcpy(acc + *len_inout, buf, copy);
					*len_inout += copy;
					acc[*len_inout] = '\0';
				}
				continue;
			}
			break;
		}
		elapsed += 25;
	}
}

static int
write_all_pty(int fd, const void *buf, size_t len)
{
	const uint8_t *p = (const uint8_t *)buf;
	size_t off = 0;
	while (off < len) {
		ssize_t n = write(fd, p + off, len - off);
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				usleep(10000);
				continue;
			}
			return -1;
		}
		off += (size_t)n;
	}
	return 0;
}

static int
verify_nano_pty_curses(const char *out_path)
{
	unlink(out_path);

	int master = -1, slave = -1;
	struct winsize ws;
	memset(&ws, 0, sizeof(ws));
	ws.ws_row = 24;
	ws.ws_col = 80;
	ws.ws_xpixel = 640;
	ws.ws_ypixel = 384;

	if (openpty(&master, &slave, NULL, NULL, &ws) != 0) {
		fprintf(stderr, "[FAIL] openpty failed: errno=%d (%s)\n", errno, strerror(errno));
		return 1;
	}

	pid_t pid = fork();
	if (pid < 0) {
		fprintf(stderr, "[FAIL] fork failed: errno=%d\n", errno);
		close(master);
		close(slave);
		return 1;
	}

	if (pid == 0) {
		close(master);
		if (login_tty(slave) != 0)
			_exit(126);
		setenv("TERM", "xterm-256color", 1);
		setenv("LC_CTYPE", "en_US.UTF-8", 1);
		setenv("HOME", "/root", 1);
		char *const nargv[] = {
			(char *)"nano",
			(char *)"--ignore",
			(char *)out_path,
			NULL
		};
		execv("/usr/local/bin/nano", nargv);
		_exit(127);
	}

	close(slave);

	size_t screen_cap = 65536;
	char *screen_buf = calloc(1, screen_cap);
	if (screen_buf == NULL) {
		close(master);
		return 1;
	}
	size_t screen_len = 0;

	/* Wait until nano initializes curses and emits ESC sequences */
	for (int attempt = 0; attempt < 40; attempt++) {
		drain_pty(master, screen_buf, screen_cap, &screen_len, 100);
		if (strstr(screen_buf, "\x1b[") != NULL && screen_len >= 32)
			break;
	}

	if (strstr(screen_buf, "\x1b[") == NULL) {
		fprintf(stderr, "[FAIL] nano did not emit curses ANSI sequences (len=%zu)\n", screen_len);
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		free(screen_buf);
		close(master);
		return 1;
	}

	/* Type UTF-8 text (without trailing CR; nano appends trailing LF on save) */
	const char payload[] = "OpenBSD WASM64 nano UTF-8 \xc3\xa9\xc3\xa0\xc3\xbc";
	if (write_all_pty(master, payload, sizeof(payload) - 1) != 0) {
		fprintf(stderr, "[FAIL] PTY write payload failed\n");
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		free(screen_buf);
		close(master);
		return 1;
	}
	drain_pty(master, screen_buf, screen_cap, &screen_len, 150);

	/* Ctrl+O (WriteOut) -> wait for filename prompt -> Enter -> wait -> Ctrl+X (Exit) */
	if (write_all_pty(master, "\x0f", 1) != 0) {
		fprintf(stderr, "[FAIL] PTY write ^O failed\n");
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		free(screen_buf);
		close(master);
		return 1;
	}
	drain_pty(master, screen_buf, screen_cap, &screen_len, 150);

	if (write_all_pty(master, "\r", 1) != 0) {
		fprintf(stderr, "[FAIL] PTY write CR failed\n");
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		free(screen_buf);
		close(master);
		return 1;
	}
	drain_pty(master, screen_buf, screen_cap, &screen_len, 200);

	/* Ctrl+X */
	(void)write_all_pty(master, "\x18", 1);

	int status = -1;
	int reaped = 0;
	for (int i = 0; i < 100; i++) {
		drain_pty(master, screen_buf, screen_cap, &screen_len, 50);
		pid_t w = waitpid(pid, &status, WNOHANG);
		if (w == pid) {
			reaped = 1;
			break;
		}
	}
	if (!reaped) {
		kill(pid, SIGTERM);
		waitpid(pid, &status, 0);
	}
	close(master);

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "[FAIL] nano PTY exited abnormally: status=0x%x\n", status);
		free(screen_buf);
		return 1;
	}

	/* Verify saved UTF-8 file contents */
	FILE *fp = fopen(out_path, "rb");
	if (fp == NULL) {
		fprintf(stderr, "[FAIL] nano did not save %s\n", out_path);
		free(screen_buf);
		return 1;
	}
	char saved[256] = {0};
	size_t nread = fread(saved, 1, sizeof(saved) - 1, fp);
	fclose(fp);

	const char expected[] = "OpenBSD WASM64 nano UTF-8 \xc3\xa9\xc3\xa0\xc3\xbc\n";
	if (nread != strlen(expected) || memcmp(saved, expected, nread) != 0) {
		fprintf(stderr, "[FAIL] nano saved mismatch: got '%s' (%zuB), expected '%s'\n",
		    saved, nread, expected);
		free(screen_buf);
		return 1;
	}

	printf("[PORTS-PASS] nano_pty_curses_utf8: 80x24 PTY curses (%zuB ANSI) + UTF-8 save verified\n",
	    screen_len);
	fflush(stdout);
	free(screen_buf);
	return 0;
}

int
main(int argc, char **argv)
{
	const char *mode = (argc > 1) ? argv[1] : "all";
	const char *nano_file = (argc > 2) ? argv[2] : "/tmp/nano_pty_probe.txt";

	if (strcmp(mode, "libs") == 0 || strcmp(mode, "all") == 0) {
		if (verify_static_libraries() != 0)
			return 1;
	}
	if (strcmp(mode, "nano-pty") == 0 || strcmp(mode, "all") == 0) {
		if (verify_nano_pty_curses(nano_file) != 0)
			return 1;
	}
	return 0;
}
