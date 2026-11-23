#include <stddef.h>
#include <stdint.h>

/*
 * Weak Itanium unwind & execinfo stubs for `-C panic=abort` Rust binaries on
 * WASM64 OpenBSD (`wasm64-unknown-openbsd`). Satisfies references from `std`
 * and `backtrace` without pulling in C++ exception unwinding tables, while
 * remaining weak so mixed Rust/C++ binaries linking `libc++abi.a` never collide.
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
