#include <sys/param.h>
#include <sys/sysctl.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Weak Itanium unwind, execinfo & pre-8.0 OpenBSD libc compatibility stubs for
 * `-C panic=abort` Rust binaries on WASM64 OpenBSD (`wasm64-unknown-openbsd`).
 */
#define OBSD_RUST_WEAK __attribute__((weak, visibility("default")))

OBSD_RUST_WEAK int
_Unwind_Backtrace(void *trace, void *trace_argument)
{
	(void)trace;
	(void)trace_argument;
	return 5; /* _URC_END_OF_STACK */
}

OBSD_RUST_WEAK uintptr_t
_Unwind_GetIP(void *ctx)
{
	(void)ctx;
	return 0;
}

OBSD_RUST_WEAK uintptr_t
_Unwind_GetIPInfo(void *ctx, int *ip_before_insn)
{
	(void)ctx;
	if (ip_before_insn != NULL)
		*ip_before_insn = 0;
	return 0;
}

OBSD_RUST_WEAK uintptr_t
_Unwind_GetCFA(void *ctx)
{
	(void)ctx;
	return 0;
}

OBSD_RUST_WEAK void *
_Unwind_FindEnclosingFunction(void *pc)
{
	(void)pc;
	return NULL;
}

OBSD_RUST_WEAK uintptr_t
_Unwind_GetDataRelBase(void *ctx)
{
	(void)ctx;
	return 0;
}

OBSD_RUST_WEAK uintptr_t
_Unwind_GetTextRelBase(void *ctx)
{
	(void)ctx;
	return 0;
}

OBSD_RUST_WEAK void *
_Unwind_GetLanguageSpecificData(void *ctx)
{
	(void)ctx;
	return NULL;
}

OBSD_RUST_WEAK uintptr_t
_Unwind_GetRegionStart(void *ctx)
{
	(void)ctx;
	return 0;
}

OBSD_RUST_WEAK void
_Unwind_SetGR(void *ctx, int index, uintptr_t val)
{
	(void)ctx;
	(void)index;
	(void)val;
}

OBSD_RUST_WEAK void
_Unwind_SetIP(void *ctx, uintptr_t val)
{
	(void)ctx;
	(void)val;
}

OBSD_RUST_WEAK void
_Unwind_DeleteException(void *exc)
{
	(void)exc;
}

OBSD_RUST_WEAK int
_Unwind_RaiseException(void *exc)
{
	(void)exc;
	return 5;
}

OBSD_RUST_WEAK void
_Unwind_Resume(void *exc)
{
	(void)exc;
	__builtin_trap();
}

OBSD_RUST_WEAK size_t
backtrace(void **addrlist, size_t len)
{
	(void)addrlist;
	(void)len;
	return 0;
}

OBSD_RUST_WEAK char **
backtrace_symbols(void *const *addrlist, size_t len)
{
	(void)addrlist;
	(void)len;
	return NULL;
}

OBSD_RUST_WEAK int
backtrace_symbols_fd(void *const *addrlist, size_t len, int fd)
{
	(void)addrlist;
	(void)len;
	(void)fd;
	return 0;
}

#if defined(OpenBSD) && (OpenBSD < 202610)
/*
 * OpenBSD 8.0 introduced `getexecpath(2)`, which Rust 1.102+ `std::env::current_exe()`
 * calls unconditionally on `target_os = "openbsd"`. Provide a weak `KERN_PROC_ARGS` +
 * `PATH` fallback for OpenBSD 7.8 and 7.9 so `std` links and resolves `current_exe()`
 * cleanly across all three supported OpenBSD releases.
 */
OBSD_RUST_WEAK int
getexecpath(char *buf, size_t len)
{
	int mib[4];
	size_t cb = 0;
	char *argbuf = NULL;
	const char *argv0 = NULL;
	char cand[PATH_MAX];
	char resolved[PATH_MAX];
	const char *out = NULL;

	if (buf == NULL || len == 0) {
		errno = EINVAL;
		return -1;
	}

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC_ARGS;
	mib[2] = (int)getpid();
	mib[3] = KERN_PROC_ARGV;
	if (sysctl(mib, 4, NULL, &cb, NULL, 0) == 0 && cb > 0) {
		argbuf = (char *)malloc(cb);
		if (argbuf != NULL) {
			if (sysctl(mib, 4, argbuf, &cb, NULL, 0) == 0) {
				char *const *vec = (char *const *)(void *)argbuf;
				if (vec[0] != NULL && vec[0][0] != '\0')
					argv0 = vec[0];
			}
		}
	}
	if (argv0 == NULL)
		argv0 = getprogname();

	if (argv0 != NULL && argv0[0] != '\0') {
		if (strchr(argv0, '/') != NULL) {
			out = realpath(argv0, resolved) != NULL ? resolved : argv0;
		} else {
			const char *path_env = getenv("PATH");
			if (path_env == NULL || path_env[0] == '\0')
				path_env = "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin";
			const char *p = path_env;
			while (*p != '\0') {
				const char *colon = strchr(p, ':');
				size_t dlen = colon != NULL ? (size_t)(colon - p) : strlen(p);
				size_t alen = strlen(argv0);
				if (dlen == 0) {
					if (alen + 3 <= sizeof(cand)) {
						cand[0] = '.';
						cand[1] = '/';
						memcpy(cand + 2, argv0, alen + 1);
						if (access(cand, X_OK) == 0) {
							out = realpath(cand, resolved) != NULL ? resolved : cand;
							break;
						}
					}
				} else if (dlen + 1 + alen + 1 <= sizeof(cand)) {
					memcpy(cand, p, dlen);
					cand[dlen] = '/';
					memcpy(cand + dlen + 1, argv0, alen + 1);
					if (access(cand, X_OK) == 0) {
						out = realpath(cand, resolved) != NULL ? resolved : cand;
						break;
					}
				}
				if (colon == NULL)
					break;
				p = colon + 1;
			}
		}
	}

	if (out == NULL) {
		free(argbuf);
		errno = ENOENT;
		return -1;
	}
	size_t n = strlen(out) + 1;
	if (n > len) {
		free(argbuf);
		errno = ERANGE;
		return -1;
	}
	memcpy(buf, out, n);
	free(argbuf);
	return 0;
}
#endif

