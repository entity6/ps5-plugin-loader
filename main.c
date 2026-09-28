#include <ps5/klog.h>
#include <ps5/kernel.h>

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <stddef.h>
#include <sys/sysctl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <machine/reg.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <time.h>

////////// SOME DEFINITIONS //////////

#define DEFAULT_INI_PATH "/data/plugins/ploader.ini"
#define MAX_PLUGINS      10  // you can change here if you want more plugins.
#define MAX_TITLES       10  // also increase this here if you want to configure it for more processes.
#define MAX_PATH_LEN     255
#define MAX_TITLE_ID_LEN 16

////////// NIDS //////////

#define NID_LOADSTARTMODULE "wzvqT4UqKX8" // sceKernelLoadStartModule
#define NID_GETPID          "HoLVWNanBBc" // getpid

////////// CREDENTIALS //////////

#define UCRED_UID     0x04
#define UCRED_RUID    0x08
#define UCRED_SVUID   0x0C
#define UCRED_NGROUPS 0x10
#define UCRED_RGID    0x14
#define UCRED_SVGID   0x18
#define UCRED_AUTHID  0x58
#define UCRED_CAPS0   0x60
#define UCRED_CAPS1   0x68
#define UCRED_ATTR0   0x83

#define AUTHID_SYSTEM   0x4801000000000013ULL // unsigned long long
#define AUTHID_DEBUGGER 0x4800000000010003ULL // unsigned long long

typedef struct {
	// standard bsd fields
	uint32_t uid;       // offset 0x04 - effective user id
	uint32_t ruid;      // offset 0x08 - real user id
	uint32_t svuid;     // offset 0x0C - saved user id
	uint32_t ngroups;   // offset 0x10 - number of groups
	uint32_t rgid;      // offset 0x14 - real group id
	uint32_t svgid;     // offset 0x18 - saved group id

	// sony proprietary fields
	uint64_t authid;    // offset 0x58 - authentication identity (sceSblACMgrGetDeviceAccessType)
	uint64_t caps0;     // offset 0x60 - capabilities block 0 (sceSblACMgrHasSceProcessCapability)
	uint64_t caps1;     // offset 0x68 - capabilities block 1
	uint8_t  attr;      // offset 0x83 - system ucred flag (sceSblACMgrIsSystemUcred)

	intptr_t rootdir; // ye
	intptr_t jaildir; // ye
} ps5_ucred_snapshot_t;

////////// SHELLCODE //////////

#define SHELLCODE_FN_OFFSET 14

/*
we preserve the first argument (RDI) and zero out the others (RSI, RDX, RCX, R8, R9).
calls the patched function pointer at offset 14 (mov r15, imm64).
it ends with INT3 (0xCC) to generate a SIGTRAP and return control to ptrace (as i saw etaHEN doing).
*/
static const uint8_t k_shellcode[] = {
	0x55,                               // push rbp
	0x48, 0x89, 0xE5,                   // mov  rbp, rsp
	0x48, 0x83, 0xE4, 0xF0,             // and  rsp, -16   (16-byte ABI alignment)
	0x48, 0x83, 0xEC, 0x28,             // sub  rsp, 0x28  (scratch space)
	0x49, 0xBF,                         // mov  r15, imm64 <- fn patched at runtime
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x31, 0xF6,                         // xor  esi, esi   (arg2 = 0)
	0x31, 0xD2,                         // xor  edx, edx   (arg3 = 0)
	0x31, 0xC9,                         // xor  ecx, ecx   (arg4 = 0)
	0x45, 0x31, 0xC0,                   // xor  r8d, r8d   (arg5 = 0)
	0x45, 0x31, 0xC9,                   // xor  r9d, r9d   (arg6 = 0)
	0x41, 0xFF, 0xD7,                   // call r15        (rdi = path, already set)
	0x48, 0x89, 0xEC,                   // mov  rsp, rbp
	0x5D,                               // pop  rbp
	0xCC                                // int3  <- tracer wakes here, RAX = result
};

////////// TYPES //////////

typedef struct {
	uint32_t app_id;
	uint64_t unknown1;
	char     title_id[16];
	char     unknown2[0x40];
} app_info_t;

typedef struct {
	char title_id[MAX_TITLE_ID_LEN + 1];
	char paths[MAX_PLUGINS][MAX_PATH_LEN + 1];
	int  modes[MAX_PLUGINS];
	int  path_count;
	int injected;
} plugin_entry_t;

////////// IMPORTS //////////

int sceKernelSendNotificationRequest(int, void*, size_t, int);
int sceKernelGetAppInfo(pid_t, app_info_t*);

////////// GLOBALS //////////

static plugin_entry_t g_plugins[MAX_TITLES];
static int            g_plugin_count = 0;

////////// NOTIFY //////////

static void notify(const char* fmt, ...) {
	char msg[256];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	struct {
		char unused[45];
		char message[3075];
	} req = { 0 };
	snprintf(req.message, sizeof(req.message), "[ploader] %s", msg);
	sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

////////// PTRACE //////////

// from github.com/ps5-payload-dev/elfldr/blob/master/pt.c
static int sys_ptrace(int req, pid_t pid, caddr_t addr, int data) {
	pid_t mypid = getpid();
	uint64_t authid = kernel_get_ucred_authid(mypid);
	if (!authid)
		return -1;

	kernel_set_ucred_authid(mypid, AUTHID_DEBUGGER);
	int ret = syscall(SYS_ptrace, req, pid, addr, data);
	int err = errno;
	kernel_set_ucred_authid(mypid, authid);
	errno = err;
	return ret;
}

static int waitpid_timeout(pid_t pid, int* status, int ms) {
	for (int i = 0; i < ms / 10; i++) {
		pid_t res = waitpid(pid, status, WNOHANG);
		if (res == pid)
			return 1;

		if (res < 0)
			return -1;

		usleep(10000);
	}
	return 0;
}

#define PT_ATTACH_RETRIES  3      // how many times to retry pt_attach before giving up
#define PT_ATTACH_DELAY_US 300000 // 300ms between attach retries

static int pt_attach(pid_t pid) {
	for (int i = 0; i < PT_ATTACH_RETRIES; i++) {
		if (kill(pid, 0) != 0)
			return -1; // process died, no point retrying

		if (sys_ptrace(PT_ATTACH, pid, 0, 0) == 0 &&
			waitpid_timeout(pid, NULL, 2000) > 0)
			return 0;

		if (errno == ESRCH)
			return -1; // process gone
		usleep(PT_ATTACH_DELAY_US);
	}
	return -1;
}

static int pt_detach(pid_t pid) {
	return sys_ptrace(PT_DETACH, pid, 0, 0);
}

static int pt_getregs(pid_t pid, struct reg* r) {
	return sys_ptrace(PT_GETREGS, pid, (caddr_t)r, 0);
}

static int pt_setregs(pid_t pid, const struct reg* r) {
	return sys_ptrace(PT_SETREGS, pid, (caddr_t)r, 0);
}

static int pt_copyin(pid_t pid, const void* buf, intptr_t addr, size_t len) {
	struct ptrace_io_desc iod = { .piod_op = PIOD_WRITE_D, .piod_offs = (void*)addr, .piod_addr = (void*)buf, .piod_len = len };
	return sys_ptrace(PT_IO, pid, (caddr_t)&iod, 0);
}

static intptr_t pt_resolve(pid_t pid, const char* nid) {
	intptr_t a = kernel_dynlib_resolve(pid, 0x1, nid);
	return a ? a : kernel_dynlib_resolve(pid, 0x2001, nid);
}

static long pt_syscall(pid_t pid, int sysno, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
	intptr_t addr = pt_resolve(pid, NID_GETPID);
	if (!addr)
		return -1;
	addr += 0xA; // skip wrapper prologue to call syscall instruction directly

	struct reg jmp, bak;
	if (pt_getregs(pid, &bak))
		return -1;

	jmp = bak;
	jmp.r_rip = addr;
	jmp.r_rax = sysno;
	jmp.r_rdi = a1;
	jmp.r_rsi = a2;
	jmp.r_rdx = a3;
	jmp.r_r10 = a4;
	jmp.r_r8 = a5;
	jmp.r_r9 = a6;

	if (pt_setregs(pid, &jmp))
		return -1;

	for (int i = 0; i < 10000; i++) {
		if (sys_ptrace(PT_STEP, pid, (caddr_t)1, 0) || waitpid_timeout(pid, NULL, 1000) <= 0)
			return -1;

		if (pt_getregs(pid, &jmp))
			return -1;

		if (jmp.r_rsp > bak.r_rsp)
			break;
	}

	pt_setregs(pid, &bak);
	return jmp.r_rax;
}

static intptr_t pt_mmap(pid_t pid, intptr_t addr, size_t len, int prot, int flags, int fd, off_t off) {
	return pt_syscall(pid, SYS_mmap, addr, len, prot, flags, fd, off);
}

static int pt_munmap(pid_t pid, intptr_t addr, size_t len) {
	return pt_syscall(pid, SYS_munmap, addr, len, 0, 0, 0, 0);
}

static long pt_call(pid_t pid, intptr_t addr, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
	struct reg jmp, bak;
	if (pt_getregs(pid, &bak))
		return -1;

	jmp = bak;
	jmp.r_rip = addr; // address
	jmp.r_rdi = a1;   // arg1
	jmp.r_rsi = a2;   // arg2
	jmp.r_rdx = a3;   // arg3
	jmp.r_rcx = a4;   // arg4
	jmp.r_r8 = a5;    // arg5
	jmp.r_r9 = a6;    // arg6

	if (pt_setregs(pid, &jmp))
		return -1;

	sys_ptrace(PT_CONTINUE, pid, (caddr_t)1, 0);

	int status = 0;
	if (waitpid_timeout(pid, &status, 30000) <= 0 || !WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) { // I increased the timeout from 5000 to 30000
		pt_setregs(pid, &bak);
		return -1;
	}

	if (pt_getregs(pid, &jmp))
		return -1;

	pt_setregs(pid, &bak);
	return jmp.r_rax;
}

////////// PROCESS //////////

static int save_creds(intptr_t ucred, ps5_ucred_snapshot_t* out, pid_t pid) {
	if (kernel_copyout(ucred + UCRED_UID, &out->uid, 4) < 0)
		return -1;
	if (kernel_copyout(ucred + UCRED_RUID, &out->ruid, 4) < 0)
		return -1;
	if (kernel_copyout(ucred + UCRED_SVUID, &out->svuid, 4) < 0)
		return -1;
	if (kernel_copyout(ucred + UCRED_NGROUPS, &out->ngroups, 4) < 0)
		return -1;
	if (kernel_copyout(ucred + UCRED_RGID, &out->rgid, 4) < 0)
		return -1;
	if (kernel_copyout(ucred + UCRED_SVGID, &out->svgid, 4) < 0)
		return -1;
	if (kernel_copyout(ucred + UCRED_AUTHID, &out->authid, 8) < 0)
		return -1;
	if (kernel_copyout(ucred + UCRED_CAPS0, &out->caps0, 8) < 0)
		return -1;
	if (kernel_copyout(ucred + UCRED_CAPS1, &out->caps1, 8) < 0)
		return -1;
	if (kernel_copyout(ucred + UCRED_ATTR0, &out->attr, 1) < 0)
		return -1;

	out->rootdir = kernel_get_proc_rootdir(pid);
	out->jaildir = kernel_get_proc_jaildir(pid);
	return 0;
}

static int restore_creds(intptr_t ucred, const ps5_ucred_snapshot_t* snap, pid_t pid) {
	if (kernel_copyin(&snap->uid, ucred + UCRED_UID, 4) < 0)
		return -1;
	if (kernel_copyin(&snap->ruid, ucred + UCRED_RUID, 4) < 0)
		return -1;
	if (kernel_copyin(&snap->svuid, ucred + UCRED_SVUID, 4) < 0)
		return -1;
	if (kernel_copyin(&snap->ngroups, ucred + UCRED_NGROUPS, 4) < 0)
		return -1;
	if (kernel_copyin(&snap->rgid, ucred + UCRED_RGID, 4) < 0)
		return -1;
	if (kernel_copyin(&snap->svgid, ucred + UCRED_SVGID, 4) < 0)
		return -1;
	if (kernel_copyin(&snap->authid, ucred + UCRED_AUTHID, 8) < 0)
		return -1;
	if (kernel_copyin(&snap->caps0, ucred + UCRED_CAPS0, 8) < 0)
		return -1;
	if (kernel_copyin(&snap->caps1, ucred + UCRED_CAPS1, 8) < 0)
		return -1;
	if (kernel_copyin(&snap->attr, ucred + UCRED_ATTR0, 1) < 0)
		return -1;

	kernel_set_proc_rootdir(pid, snap->rootdir);
	kernel_set_proc_jaildir(pid, snap->jaildir);
	return 0;
}

// necessary for the loader to be able to see everything starting from '/'
static int jb_pid(pid_t pid, intptr_t ucred) {
	intptr_t rv = kernel_get_root_vnode();

	if (!rv || !ucred)
		return -1;

	uint32_t zero = 0;
	int64_t  caps = -1LL;
	uint64_t authid = AUTHID_SYSTEM;
	uint8_t  attr = 0x80;

	kernel_copyin(&zero, ucred + UCRED_UID, 4);
	kernel_copyin(&zero, ucred + UCRED_RUID, 4);
	kernel_copyin(&zero, ucred + UCRED_SVUID, 4);
	kernel_copyin(&zero, ucred + UCRED_NGROUPS, 4);
	kernel_copyin(&zero, ucred + UCRED_RGID, 4);
	kernel_copyin(&zero, ucred + UCRED_SVGID, 4);
	kernel_copyin(&authid, ucred + UCRED_AUTHID, 8);
	kernel_copyin(&caps, ucred + UCRED_CAPS0, 8);
	kernel_copyin(&caps, ucred + UCRED_CAPS1, 8);
	kernel_copyin(&attr, ucred + UCRED_ATTR0, 1);

	// that alone is sufficient but im going to keep raising the other fields.
	kernel_set_proc_rootdir(pid, rv);
	kernel_set_proc_jaildir(pid, rv);

	return 0;
}

static int get_all_pids(pid_t* pids, int max_pids) {
	int mib[4] = { 1, 14, 8, 0 }; // if you use 'CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0' directly, it won't find the process.
	size_t sz = 0;
	if (sysctl(mib, 4, NULL, &sz, NULL, 0) < 0) return 0;

	uint8_t* buf = malloc(sz);
	if (!buf) return 0;
	if (sysctl(mib, 4, buf, &sz, NULL, 0) < 0) { free(buf); return 0; }

	int count = 0;
	for (uint8_t* p = buf; p + 4 <= buf + sz; ) {
		int elen = *(int*)p;
		if (elen <= 0 || p + elen > buf + sz) break;
		pid_t pid = *(pid_t*)(p + 0x48);
		if (pid > 1 && count < max_pids)
			pids[count++] = pid;
		p += elen;
	}
	free(buf);
	return count;
}

// returns 1 if all configured titles have already been injected
static int all_injected(void) {
	for (int i = 0; i < g_plugin_count; i++)
		if (!g_plugins[i].injected)
			return 0;
	return 1;
}

// looks for a title entry by title_id
static plugin_entry_t* find_entry(const char* title_id) {
	for (int i = 0; i < g_plugin_count; i++)
		if (strcmp(g_plugins[i].title_id, title_id) == 0)
			return &g_plugins[i];
	return NULL;
}

static const char* get_filename(const char* path) {
	const char* name = strrchr(path, '/');
	return name ? name + 1 : path;
}

////////// INJECTION //////////

static int inject_prx(pid_t pid, const char* prx_path) {
	if (access(prx_path, R_OK) != 0)
		return -1;

	intptr_t fn = pt_resolve(pid, NID_LOADSTARTMODULE);
	if (!fn)
		return -1;

	// allocate a temporary anonymous read/write memory page at a kernel-selected address using 'mmap'.
	intptr_t rw_page = pt_mmap(pid, 0, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (rw_page <= 0)
		return -1;

	intptr_t remote_path = rw_page;
	intptr_t remote_sc = rw_page + 0x1000;
	int mod = -1;

	if (pt_copyin(pid, prx_path, remote_path, strlen(prx_path) + 1) >= 0) {
		uint8_t sc[sizeof(k_shellcode)];
		memcpy(sc, k_shellcode, sizeof(sc));
		memcpy(sc + SHELLCODE_FN_OFFSET, &fn, sizeof(fn));

		if (pt_copyin(pid, sc, remote_sc, sizeof(sc)) >= 0) {
			kernel_mprotect(pid, remote_sc, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);
			mod = pt_call(pid, remote_sc, remote_path, 0, 0, 0, 0, 0);
			kernel_mprotect(pid, remote_sc, 0x1000, PROT_READ | PROT_WRITE);
		}
	}

	pt_munmap(pid, rw_page, 0x4000);
	return mod;
}

////////// TIME //////////

#define MAX_DEP_NAME_LEN 64
#define MAX_DEPS         8

// timing parameters per injection mode
typedef struct {
	int stable_ms;
	int min_mod;
	int settle_ms;
} mode_params_t;

// returns timing parameters for a given mode
// mode 1 (early): inject soon, few modules, short settle
// mode 2 (late):  inject late, many modules, long settle
static mode_params_t get_mode_params(int mode) {
	if (mode == 1)
		return (mode_params_t) { .stable_ms = 150, .min_mod = 6, .settle_ms = 150 };
	else
		return (mode_params_t) { .stable_ms = 1000, .min_mod = 16, .settle_ms = 600 };
}

// libs present in any ps5 process, enough for basic timing
static int collect_needs(char needs[][MAX_DEP_NAME_LEN], int max) {
	static const char* core[] = {
		"libkernel.sprx",
		"libc.prx",
		"libSceFios2.prx"
	};
	int n = 0;
	for (size_t i = 0; i < sizeof(core) / sizeof(core[0]) && n < max; i++)
		snprintf(needs[n++], MAX_DEP_NAME_LEN, "%s", core[i]);
	return n;
}

// counts how many modules the process has loaded at the moment
static int count_modules(pid_t pid) {
	int count = 0;
	for (uint32_t h = 0; h < 0x40; h++)
		if (kernel_dynlib_mapbase_addr(pid, h)) count++;
	for (uint32_t h = 0x2000; h < 0x2040; h++)
		if (kernel_dynlib_mapbase_addr(pid, h)) count++;
	return count;
}

// checks if a specific dependency is already loaded in the process
static int dep_present(pid_t pid, const char* basename) {
	uint32_t h = 0;
	if (kernel_dynlib_handle(pid, basename, &h) != 0) return 0;
	return kernel_dynlib_mapbase_addr(pid, h) != 0;
}

// checks if all needed deps are loaded and the module count meets the minimum
static int deps_ready(pid_t pid, char needs[][MAX_DEP_NAME_LEN], int nneeds, int min_mod) {
	for (int i = 0; i < nneeds; i++)
		if (!dep_present(pid, needs[i])) return 0;
	if (!pt_resolve(pid, NID_LOADSTARTMODULE)) return 0;
	return count_modules(pid) >= min_mod;
}

// waits for the process to reach stable state, then settles before returning
// returns 1 when ready, 0 if process died
static int wait_stable(pid_t pid, char needs[][MAX_DEP_NAME_LEN], int nneeds,
	const mode_params_t* mp, int max_ms) {
	const int tick_ms = 50;
	const int stable_req = (mp->stable_ms / tick_ms) < 2 ? 2 : (mp->stable_ms / tick_ms);
	const int max_ticks = max_ms / tick_ms;

	int stable_hits = 0;
	int prev_count = -1;

	for (int t = 0; t < max_ticks; t++) {
		if (kill(pid, 0) != 0)
			return 0; // process died

		int cur = count_modules(pid);

		// reset stability counter if module count changed
		if (cur != prev_count && prev_count >= 0)
			stable_hits = 0;
		prev_count = cur;

		if (deps_ready(pid, needs, nneeds, mp->min_mod)) {
			if (++stable_hits >= stable_req) {
				usleep(mp->settle_ms * 1000); // wait for things to settle
				if (kill(pid, 0) != 0) return 0;

				// verify again after settle
				if (deps_ready(pid, needs, nneeds, mp->min_mod))
					return 1; // ready!

				stable_hits = 0;
			}
		}
		else {
			stable_hits = 0;
		}

		usleep(tick_ms * 1000);
	}

	// try anyway if the process is still alive
	return kill(pid, 0) == 0 ? 1 : 0;
}

// waits for the process to reach the right state based on mode
// returns 1 when ready, 0 if process died
static int wait_for_needs(pid_t pid, char needs[][MAX_DEP_NAME_LEN], int nneeds, int mode, int max_ms) {
	mode_params_t mp = get_mode_params(mode);
	return wait_stable(pid, needs, nneeds, &mp, max_ms);
}

static struct timespec g_t0;

static long now_ms(void) {
	struct timespec n;
	clock_gettime(CLOCK_MONOTONIC, &n);
	return (n.tv_sec - g_t0.tv_sec) * 1000L + (n.tv_nsec - g_t0.tv_nsec) / 1000000L;
}

////////// INI PARSER //////////

// strips leading and trailing whitespace in-place, returns pointer to trimmed string
static char* trim(char* s) {
	while (*s == ' ' || *s == '\t') s++;
	char* end = s + strlen(s) - 1;
	while (end > s && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n'))
		*end-- = '\0';
	return s;
}

// returns 1 if the line is a comment or empty
static int is_blank_or_comment(const char* s) {
	return *s == '\0' || *s == ';' || *s == '#';
}

// parses a section header like [CUSA12345], writes title id into out, returns 1 on success
static int parse_section(const char* s, char* out, size_t outsz) {
	size_t len = strlen(s);
	if (s[0] != '[' || s[len - 1] != ']') return 0;
	snprintf(out, outsz, "%.*s", (int)(len - 2), s + 1);
	return 1;
}

// parses the injection mode from the value string
// 0 = disabled
// 1 = early
// 2 = late
// inline comments after the value are ignored (e.g. "1 ; this is early")
static int parse_mode(const char* val) {
	int mode = atoi(val); // atoi stops at the first non-numeric character, so inline comments are safe
	if (mode < 0 || mode > 2)
		return -1;
	return mode;
}

// validates and normalizes a plugin path, returns 1 if valid
static int normalize_path(char* p, char* out, size_t outsz) {
	p = trim(p);
	if (!*p || strlen(p) > MAX_PATH_LEN || strstr(p, ".."))
		return 0;
	// if no slash, assume /data/plugins/ prefix
	if (!strchr(p, '/'))
		snprintf(out, outsz, "/data/plugins/%s", p);
	else
		snprintf(out, outsz, "%s", p);
	return 1;
}

// finds or creates a slot for the given title id, returns slot index or -1
static int get_or_create_slot(const char* tid) {
	for (int i = 0; i < g_plugin_count; i++)
		if (strcmp(g_plugins[i].title_id, tid) == 0)
			return i;

	if (g_plugin_count >= MAX_TITLES)
		return -1;

	int slot = g_plugin_count++;
	snprintf(g_plugins[slot].title_id, sizeof(g_plugins[slot].title_id), "%s", tid);
	g_plugins[slot].path_count = 0;
	g_plugins[slot].injected = 0;
	return slot;
}

// registers a plugin entry into its title slot
static void register_plugin(int slot, const char* path, int mode) {
	if (slot < 0 || g_plugins[slot].path_count >= MAX_PLUGINS)
		return;
	int idx = g_plugins[slot].path_count++;
	snprintf(g_plugins[slot].paths[idx], MAX_PATH_LEN + 1, "%s", path);
	g_plugins[slot].modes[idx] = mode;
}

// reads and parses the .ini config file
static void read_ini(const char* path) {
	FILE* f = fopen(path, "r");
	if (!f) return;

	char line[1024];
	char tid[MAX_TITLE_ID_LEN + 1] = { 0 };

	while (fgets(line, sizeof(line), f)) {
		char* s = trim(line);

		if (is_blank_or_comment(s)) continue;

		if (parse_section(s, tid, sizeof(tid))) continue;

		if (!*tid) continue;

		char* eq = strchr(s, '=');
		if (!eq) continue;
		*eq = '\0';

		int mode = parse_mode(trim(eq + 1));
		if (mode <= 0) continue; // -1 = invalid, 0 = disabled

		char normalized[MAX_PATH_LEN + 1];
		if (!normalize_path(s, normalized, sizeof(normalized)))
			continue;

		int slot = get_or_create_slot(tid);
		register_plugin(slot, normalized, mode);
	}

	fclose(f);
}

////////// LOCKER //////////

#define LOCK_PATH "/data/plugins/ploader.lock"

// writes our pid to the lock file, returns 1 on success
static int lock_acquire(void) {
	// check if another instance is already running
	FILE* f = fopen(LOCK_PATH, "r");
	if (f) {
		char buf[32] = { 0 };
		fread(buf, 1, sizeof(buf) - 1, f);
		fclose(f);

		pid_t other = (pid_t)atoi(buf);
		if (other > 1 && kill(other, 0) == 0) {
			notify("Already running (pid %d), exiting", other);
			return 0; // other instance is alive
		}
		// stale lock - previous instance died without cleanup
		unlink(LOCK_PATH);
	}

	f = fopen(LOCK_PATH, "w");
	if (!f)
		return 0;
	fprintf(f, "%d", getpid());
	fclose(f);
	return 1;
}

// removes the lock file if it belongs to us
static void lock_release(void) {
	char mine[32];
	snprintf(mine, sizeof(mine), "%d", getpid());

	FILE* f = fopen(LOCK_PATH, "r");
	if (!f)
		return;

	char buf[32] = { 0 };
	fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);

	// only delete if the lock is ours
	if (strcmp(buf, mine) == 0)
		unlink(LOCK_PATH);
}

////////// RUN //////////

#define INJECTOR_TIMEOUT_S 120
#define MAX_KNOWN_PIDS 512

static void run_plugins(void) {
	pid_t known[MAX_KNOWN_PIDS];
	int   known_count = get_all_pids(known, MAX_KNOWN_PIDS);

	struct timespec start, now;
	clock_gettime(CLOCK_MONOTONIC, &start);

	while (!all_injected()) {
		clock_gettime(CLOCK_MONOTONIC, &now);
		if ((now.tv_sec - start.tv_sec) >= INJECTOR_TIMEOUT_S) {
			notify("Timeout, shutting down.");
			break;
		}

		pid_t cur[MAX_KNOWN_PIDS];
		int   cur_count = get_all_pids(cur, MAX_KNOWN_PIDS);

		for (int i = 0; i < cur_count && !all_injected(); i++) {
			pid_t pid = cur[i];

			int already = 0;
			for (int j = 0; j < known_count; j++)
				if (known[j] == pid) { already = 1; break; }
			if (already) continue;

			if (known_count < MAX_KNOWN_PIDS)
				known[known_count++] = pid;

			app_info_t info = { 0 };
			if (sceKernelGetAppInfo(pid, &info) != 0 || info.title_id[0] == '\0')
				continue;

			plugin_entry_t* entry = find_entry(info.title_id);
			if (!entry || entry->injected) continue;

			notify("[%s] Injecting %d plugin(s)", entry->title_id, entry->path_count);

			int all_ok = 1;
			for (int p = 0; p < entry->path_count; p++) {
				const char* path = entry->paths[p];
				int         mode = entry->modes[p];
				int         max_ms = (mode == 2) ? 25000 : 18000;

				char needs[MAX_DEPS][MAX_DEP_NAME_LEN];
				int  nneeds = collect_needs(needs, MAX_DEPS);

				if (!wait_for_needs(pid, needs, nneeds, mode, max_ms)) {
					notify("[%s] The case died while waiting '%s'", entry->title_id, get_filename(path));
					all_ok = 0;
					break;
				}

				if (pt_attach(pid) < 0) {
					notify("[%s] Attach failed for '%s'", entry->title_id, get_filename(path));
					all_ok = 0;
					continue;
				}

				intptr_t ucred = kernel_get_proc_ucred(pid);
				ps5_ucred_snapshot_t saved = { 0 };
				if (!ucred || save_creds(ucred, &saved, pid) != 0) {
					pt_detach(pid);
					all_ok = 0;
					continue;
				}

				jb_pid(pid, ucred);

				long t0 = now_ms();
				int  rc = inject_prx(pid, path);
				long dt = now_ms() - t0;

				int ok = (rc > 0);
				if (ok)
					notify("[%s] OK (%ldms): %s", entry->title_id, dt, get_filename(path));
				else
					notify("[%s] FAIL (%ldms): %s", entry->title_id, dt, get_filename(path));

				restore_creds(ucred, &saved, pid);
				pt_detach(pid);

				if (!ok) all_ok = 0;
			}

			if (all_ok) entry->injected = 1;
		}

		usleep(50000); // 50ms
	}
}

////////// MAIN //////////

int main(void) {
	clock_gettime(CLOCK_MONOTONIC, &g_t0);
	signal(SIGSEGV, SIG_DFL);
	signal(SIGBUS, SIG_DFL);

	if (!lock_acquire()) // just to prevent us from injecting ourselves twice
		return 0;

	read_ini(DEFAULT_INI_PATH);
	if (g_plugin_count == 0) {
		notify("Config empty");
		lock_release();
		return 0;
	}

	notify("Injector started");
	run_plugins();
	notify("Finished");

	lock_release();
	return 0;
}