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

	printf("[PORTS-PASS] static_libs_c_api: bzip2=%s lzma=%s zstd=%u sqlite=%s lua=%s curl=%s(%s)\n",
	    bz_ver, xz_ver, zstd_ver, sqlite3_libversion(), LUA_RELEASE,
	    cv->version, cv->ssl_version);
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
