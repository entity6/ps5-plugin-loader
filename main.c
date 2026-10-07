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
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>

#define DEFAULT_TOML_PATH "/data/plugins/ploader.toml"
#define LOCK_PATH         "/data/plugins/ploader.lock"

#define MAX_PLUGINS       10
#define MAX_TITLES        10
#define MAX_PATH_LEN      255
#define MAX_TITLE_ID_LEN  16
#define MAX_LINE_LEN      1024
#define MAX_KNOWN_PIDS    512

#define NID_LOADSTARTMODULE "wzvqT4UqKX8"
#define NID_GETPID          "HoLVWNanBBc"

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

#define AUTHID_SYSTEM   0x4801000000000013ULL
#define AUTHID_DEBUGGER 0x4800000000010003ULL

#define SHELLCODE_FN_OFFSET 14

typedef struct {
	uint32_t uid;
	uint32_t ruid;
	uint32_t svuid;
	uint32_t ngroups;
	uint32_t rgid;
	uint32_t svgid;
	uint64_t authid;
	uint64_t caps0;
	uint64_t caps1;
	uint8_t  attr;
	intptr_t rootdir;
	intptr_t jaildir;
} ps5_ucred_snapshot_t;

static const uint8_t k_shellcode[] = {
	0x55,
	0x48, 0x89, 0xE5,
	0x48, 0x83, 0xE4, 0xF0,
	0x48, 0x83, 0xEC, 0x28,
	0x49, 0xBF,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x31, 0xF6,
	0x31, 0xD2,
	0x31, 0xC9,
	0x45, 0x31, 0xC0,
	0x45, 0x31, 0xC9,
	0x41, 0xFF, 0xD7,
	0x48, 0x89, 0xEC,
	0x5D,
	0xCC
};

typedef struct {
	uint32_t app_id;
	uint64_t unknown1;
	char     title_id[16];
	char     unknown2[0x40];
} app_info_t;

typedef struct {
	char title_id[MAX_TITLE_ID_LEN + 1];
	char paths[MAX_PLUGINS][MAX_PATH_LEN + 1];
	int  delays[MAX_PLUGINS];
	int  injects[MAX_PLUGINS];
	int  restores[MAX_PLUGINS];
	int  path_count;
} plugin_entry_t;

typedef struct {
	int active;
	pid_t pid;
	char title_id[MAX_TITLE_ID_LEN + 1];
	long created_ms;
	long retry_at_ms;
	int injected[MAX_PLUGINS];
	int started[MAX_PLUGINS];
} target_state_t;

typedef struct {
	int active;
	char title[MAX_TITLE_ID_LEN + 1];
	char path[MAX_PATH_LEN + 1];
	int delay_ms;
	int has_delay;
	int inject;
	int has_inject;
	int restore;
	int has_restore;
} pending_plugin_t;

int sceKernelGetAppInfo(pid_t, app_info_t*);
int sceKernelSendNotificationRequest(int, const void*, size_t, int);

static plugin_entry_t g_plugins[MAX_TITLES];
static int g_plugin_count = 0;

static target_state_t g_targets[MAX_KNOWN_PIDS];
static int g_target_count = 0;

static struct timespec g_t0;

static int g_timeout_s = 120;
static int g_scan_existing = 1;
static int g_default_inject = 1;
static int g_default_restore = 1;

static long now_ms(void) {
	struct timespec n;
	clock_gettime(CLOCK_MONOTONIC, &n);
	return (n.tv_sec - g_t0.tv_sec) * 1000L + (n.tv_nsec - g_t0.tv_nsec) / 1000000L;
}

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

static int pid_alive(pid_t pid) {
	if (pid <= 1)
		return 0;

	if (kill(pid, 0) == 0)
		return 1;

	if (errno == EPERM)
		return 1;

	if (errno == ESRCH)
		return 0;

	return -1;
}

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
	if (ms < 0)
		ms = 0;

	int elapsed = 0;
	const int step_ms = 10;

	for (;;) {
		pid_t res = waitpid(pid, status, WNOHANG);
		if (res == pid)
			return 1;

		if (res < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}

		if (elapsed >= ms)
			return 0;

		int sleep_ms = ms - elapsed;
		if (sleep_ms > step_ms)
			sleep_ms = step_ms;

		usleep((useconds_t)sleep_ms * 1000U);
		elapsed += sleep_ms;
	}
}

static int pt_attach(pid_t pid) {
	for (int i = 0; i < 3; i++) {
		int alive = pid_alive(pid);
		if (alive <= 0)
			return -1;

		if (sys_ptrace(PT_ATTACH, pid, 0, 0) == 0) {
			int status = 0;
			int waited = waitpid_timeout(pid, &status, 2000);

			if (waited > 0)
				return 0;

			sys_ptrace(PT_DETACH, pid, 0, 0);

			if (waited < 0 && errno == ESRCH)
				return -1;
		}

		if (errno == ESRCH)
			return -1;

		usleep(300000);
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
	struct ptrace_io_desc iod;
	iod.piod_op = PIOD_WRITE_D;
	iod.piod_offs = (void*)addr;
	iod.piod_addr = (void*)buf;
	iod.piod_len = len;
	return sys_ptrace(PT_IO, pid, (caddr_t)&iod, 0);
}

static intptr_t pt_resolve(pid_t pid, const char* nid) {
	intptr_t a = kernel_dynlib_resolve(pid, 0x1, nid);
	return a ? a : kernel_dynlib_resolve(pid, 0x2001, nid);
}

static long pt_syscall(pid_t pid, int sysno, uint64_t a1, uint64_t a2, uint64_t a3,
	uint64_t a4, uint64_t a5, uint64_t a6) {
	intptr_t addr = pt_resolve(pid, NID_GETPID);
	if (!addr)
		return -1;

	addr += 0xA;

	struct reg jmp;
	struct reg bak;

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

	if (pt_setregs(pid, &jmp)) {
		pt_setregs(pid, &bak);
		return -1;
	}

	int completed = 0;

	for (int i = 0; i < 10000; i++) {
		int status = 0;

		if (sys_ptrace(PT_STEP, pid, (caddr_t)1, 0) ||
			waitpid_timeout(pid, &status, 1000) <= 0 ||
			!WIFSTOPPED(status)) {
			pt_setregs(pid, &bak);
			return -1;
		}

		if (pt_getregs(pid, &jmp)) {
			pt_setregs(pid, &bak);
			return -1;
		}

		if (jmp.r_rsp > bak.r_rsp) {
			completed = 1;
			break;
		}
	}

	long ret = completed ? (long)jmp.r_rax : -1;
	pt_setregs(pid, &bak);
	return ret;
}

static intptr_t pt_mmap(pid_t pid, intptr_t addr, size_t len, int prot, int flags, int fd, off_t off) {
	return pt_syscall(pid, SYS_mmap, addr, len, prot, flags, fd, off);
}

static int pt_munmap(pid_t pid, intptr_t addr, size_t len) {
	return pt_syscall(pid, SYS_munmap, addr, len, 0, 0, 0, 0);
}

static long pt_call(pid_t pid, intptr_t addr, uint64_t a1, uint64_t a2, uint64_t a3,
	uint64_t a4, uint64_t a5, uint64_t a6) {
	struct reg jmp;
	struct reg bak;

	if (!addr)
		return -1;

	if (pt_getregs(pid, &bak))
		return -1;

	jmp = bak;
	jmp.r_rip = addr;
	jmp.r_rdi = a1;
	jmp.r_rsi = a2;
	jmp.r_rdx = a3;
	jmp.r_rcx = a4;
	jmp.r_r8 = a5;
	jmp.r_r9 = a6;

	if (pt_setregs(pid, &jmp)) {
		pt_setregs(pid, &bak);
		return -1;
	}

	if (sys_ptrace(PT_CONTINUE, pid, (caddr_t)1, 0) < 0) {
		pt_setregs(pid, &bak);
		return -1;
	}

	int status = 0;
	if (waitpid_timeout(pid, &status, 30000) <= 0 ||
		!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
		pt_setregs(pid, &bak);
		return -1;
	}

	if (pt_getregs(pid, &jmp)) {
		pt_setregs(pid, &bak);
		return -1;
	}

	long ret = jmp.r_rax;
	pt_setregs(pid, &bak);
	return ret;
}

static int save_creds(intptr_t ucred, ps5_ucred_snapshot_t* out, pid_t pid) {
	if (!ucred || !out || pid <= 1)
		return -1;

	if (kernel_copyout(ucred + UCRED_UID, &out->uid, 4) < 0) return -1;
	if (kernel_copyout(ucred + UCRED_RUID, &out->ruid, 4) < 0) return -1;
	if (kernel_copyout(ucred + UCRED_SVUID, &out->svuid, 4) < 0) return -1;
	if (kernel_copyout(ucred + UCRED_NGROUPS, &out->ngroups, 4) < 0) return -1;
	if (kernel_copyout(ucred + UCRED_RGID, &out->rgid, 4) < 0) return -1;
	if (kernel_copyout(ucred + UCRED_SVGID, &out->svgid, 4) < 0) return -1;
	if (kernel_copyout(ucred + UCRED_AUTHID, &out->authid, 8) < 0) return -1;
	if (kernel_copyout(ucred + UCRED_CAPS0, &out->caps0, 8) < 0) return -1;
	if (kernel_copyout(ucred + UCRED_CAPS1, &out->caps1, 8) < 0) return -1;
	if (kernel_copyout(ucred + UCRED_ATTR0, &out->attr, 1) < 0) return -1;

	out->rootdir = kernel_get_proc_rootdir(pid);
	out->jaildir = kernel_get_proc_jaildir(pid);

	if (!out->rootdir || !out->jaildir)
		return -1;

	return 0;
}

static int restore_creds(intptr_t ucred, const ps5_ucred_snapshot_t* snap, pid_t pid) {
	if (!ucred || !snap || pid <= 1)
		return -1;

	if (kernel_copyin(&snap->uid, ucred + UCRED_UID, 4) < 0) return -1;
	if (kernel_copyin(&snap->ruid, ucred + UCRED_RUID, 4) < 0) return -1;
	if (kernel_copyin(&snap->svuid, ucred + UCRED_SVUID, 4) < 0) return -1;
	if (kernel_copyin(&snap->ngroups, ucred + UCRED_NGROUPS, 4) < 0) return -1;
	if (kernel_copyin(&snap->rgid, ucred + UCRED_RGID, 4) < 0) return -1;
	if (kernel_copyin(&snap->svgid, ucred + UCRED_SVGID, 4) < 0) return -1;
	if (kernel_copyin(&snap->authid, ucred + UCRED_AUTHID, 8) < 0) return -1;
	if (kernel_copyin(&snap->caps0, ucred + UCRED_CAPS0, 8) < 0) return -1;
	if (kernel_copyin(&snap->caps1, ucred + UCRED_CAPS1, 8) < 0) return -1;
	if (kernel_copyin(&snap->attr, ucred + UCRED_ATTR0, 1) < 0) return -1;

	kernel_set_proc_rootdir(pid, snap->rootdir);
	kernel_set_proc_jaildir(pid, snap->jaildir);
	return 0;
}

static int jb_pid(pid_t pid, intptr_t ucred) {
	intptr_t rv = kernel_get_root_vnode();
	if (pid <= 1 || !rv || !ucred)
		return -1;

	uint32_t zero = 0;
	int64_t caps = -1LL;
	uint64_t authid = AUTHID_SYSTEM;
	uint8_t attr = 0x80;

	if (kernel_copyin(&zero, ucred + UCRED_UID, 4) < 0) return -1;
	if (kernel_copyin(&zero, ucred + UCRED_RUID, 4) < 0) return -1;
	if (kernel_copyin(&zero, ucred + UCRED_SVUID, 4) < 0) return -1;
	if (kernel_copyin(&zero, ucred + UCRED_NGROUPS, 4) < 0) return -1;
	if (kernel_copyin(&zero, ucred + UCRED_RGID, 4) < 0) return -1;
	if (kernel_copyin(&zero, ucred + UCRED_SVGID, 4) < 0) return -1;
	if (kernel_copyin(&authid, ucred + UCRED_AUTHID, 8) < 0) return -1;
	if (kernel_copyin(&caps, ucred + UCRED_CAPS0, 8) < 0) return -1;
	if (kernel_copyin(&caps, ucred + UCRED_CAPS1, 8) < 0) return -1;
	if (kernel_copyin(&attr, ucred + UCRED_ATTR0, 1) < 0) return -1;

	kernel_set_proc_rootdir(pid, rv);
	kernel_set_proc_jaildir(pid, rv);
	return 0;
}

static int get_all_pids(pid_t* pids, int max_pids) {
	int mib[4] = { 1, 14, 8, 0 };
	size_t sz = 0;

	if (sysctl(mib, 4, NULL, &sz, NULL, 0) < 0)
		return 0;

	uint8_t* buf = malloc(sz);
	if (!buf)
		return 0;

	if (sysctl(mib, 4, buf, &sz, NULL, 0) < 0) {
		free(buf);
		return 0;
	}

	int count = 0;
	for (uint8_t* p = buf; p + 0x4C <= buf + sz;) {
		int elen = *(int*)p;
		if (elen < 0x4C || p + elen > buf + sz)
			break;

		pid_t pid = *(pid_t*)(p + 0x48);
		if (pid > 1 && count < max_pids)
			pids[count++] = pid;

		p += elen;
	}

	free(buf);
	return count;
}

static int target_all_injected(const plugin_entry_t* entry, const target_state_t* target) {
	if (!entry || !target)
		return 0;

	for (int i = 0; i < entry->path_count; i++) {
		if (entry->injects[i] && !target->injected[i])
			return 0;
	}

	return 1;
}

static target_state_t* find_target(pid_t pid) {
	for (int i = 0; i < g_target_count; i++) {
		if (g_targets[i].active && g_targets[i].pid == pid)
			return &g_targets[i];
	}

	return NULL;
}

static target_state_t* create_target(pid_t pid, const char* title_id) {
	if (pid <= 1 || !title_id || !*title_id || g_target_count >= MAX_KNOWN_PIDS)
		return NULL;

	target_state_t* target = &g_targets[g_target_count++];
	memset(target, 0, sizeof(*target));

	target->active = 1;
	target->pid = pid;
	strncpy(target->title_id, title_id, MAX_TITLE_ID_LEN);
	target->title_id[MAX_TITLE_ID_LEN] = '\0';
	target->created_ms = now_ms();
	target->retry_at_ms = target->created_ms;
	return target;
}

static void remove_target(int index) {
	if (index < 0 || index >= g_target_count)
		return;

	if (index + 1 < g_target_count)
		memmove(&g_targets[index], &g_targets[index + 1],
			(size_t)(g_target_count - index - 1) * sizeof(g_targets[0]));

	g_target_count--;
}

static int pid_list_contains(const pid_t* pids, int count, pid_t pid) {
	if (!pids || pid <= 1)
		return 0;

	for (int i = 0; i < count; i++) {
		if (pids[i] == pid)
			return 1;
	}

	return 0;
}

static int pid_list_add(pid_t* pids, int* count, int max_pids, pid_t pid) {
	if (!pids || !count || *count >= max_pids || pid <= 1)
		return 0;

	if (pid_list_contains(pids, *count, pid))
		return 1;

	pids[(*count)++] = pid;
	return 1;
}

static void prune_dead_pids(pid_t* pids, int* count) {
	if (!pids || !count)
		return;

	for (int i = 0; i < *count;) {
		int alive = pid_alive(pids[i]);

		if (alive == 0) {
			pids[i] = pids[*count - 1];
			(*count)--;
			continue;
		}

		i++;
	}
}

static plugin_entry_t* find_entry(const char* title_id) {
	for (int i = 0; i < g_plugin_count; i++) {
		if (strcmp(g_plugins[i].title_id, title_id) == 0)
			return &g_plugins[i];
	}
	return NULL;
}

static const char* get_filename(const char* path) {
	const char* name = strrchr(path, '/');
	return name ? name + 1 : path;
}

static int inject_prx(pid_t pid, const char* prx_path) {
	if (access(prx_path, R_OK) != 0)
		return -1;

	intptr_t fn = pt_resolve(pid, NID_LOADSTARTMODULE);
	if (!fn)
		return -1;

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

static char* trim(char* s) {
	if (!s)
		return s;

	while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
		s++;

	if (!*s)
		return s;

	char* end = s + strlen(s) - 1;
	while (end > s && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n'))
		*end-- = '\0';

	return s;
}

static int is_blank_or_comment(const char* s) {
	if (!s)
		return 1;

	while (*s == ' ' || *s == '\t')
		s++;

	return *s == '\0' || *s == ';' || *s == '#';
}

static void strip_comment(char* line) {
	int inq = 0;

	for (char* p = line; *p; p++) {
		if (*p == '"')
			inq = !inq;
		else if (!inq && (*p == '#' || *p == ';')) {
			*p = '\0';
			break;
		}
	}
}

static int parse_array_table(const char* s, char* out, size_t outsz) {
	if (!s || !out || outsz == 0)
		return 0;

	size_t len = strlen(s);
	if (len < 5 || s[0] != '[' || s[1] != '[' || s[len - 2] != ']' || s[len - 1] != ']')
		return 0;

	size_t clen = len - 4;
	if (clen >= outsz)
		clen = outsz - 1;

	memcpy(out, s + 2, clen);
	out[clen] = '\0';
	trim(out);
	return 1;
}

static int parse_table(const char* s, char* out, size_t outsz) {
	if (!s || !out || outsz == 0)
		return 0;

	size_t len = strlen(s);
	if (len < 3 || s[0] != '[' || s[len - 1] != ']' || s[1] == '[')
		return 0;

	size_t clen = len - 2;
	if (clen >= outsz)
		clen = outsz - 1;

	memcpy(out, s + 1, clen);
	out[clen] = '\0';
	trim(out);
	return 1;
}

static int split_key_value(char* s, char** key, char** val) {
	char* eq = strchr(s, '=');
	if (!eq)
		return 0;

	*eq = '\0';
	*key = trim(s);
	*val = trim(eq + 1);

	if (!**key)
		return 0;

	return 1;
}

static int parse_string_value(const char* val, char* out, size_t outsz) {
	if (!val || !out || outsz == 0)
		return 0;

	while (*val == ' ' || *val == '\t')
		val++;

	if (*val == '"') {
		val++;
		const char* end = strrchr(val, '"');
		if (!end)
			return 0;

		size_t len = (size_t)(end - val);
		if (len >= outsz)
			len = outsz - 1;

		memcpy(out, val, len);
		out[len] = '\0';
		trim(out);
		return 1;
	}

	size_t len = strlen(val);
	if (len >= outsz)
		len = outsz - 1;

	memcpy(out, val, len);
	out[len] = '\0';
	trim(out);
	return 1;
}

static int parse_bool_value(const char* val, int* out) {
	if (!val || !out)
		return 0;

	if (strcmp(val, "true") == 0 || strcmp(val, "1") == 0) {
		*out = 1;
		return 1;
	}

	if (strcmp(val, "false") == 0 || strcmp(val, "0") == 0) {
		*out = 0;
		return 1;
	}

	return 0;
}

static int parse_int_value(const char* val, int* out) {
	if (!val || !out)
		return 0;

	errno = 0;
	char* endptr = NULL;
	long x = strtol(val, &endptr, 10);

	if (endptr == val || errno == ERANGE || x < INT_MIN || x > INT_MAX)
		return 0;

	while (*endptr == ' ' || *endptr == '\t')
		endptr++;

	if (*endptr != '\0')
		return 0;

	*out = (int)x;
	return 1;
}

static int normalize_path(const char* p, char* out, size_t outsz) {
	if (!p || !out || outsz == 0)
		return 0;

	while (*p == ' ' || *p == '\t')
		p++;

	if (!*p)
		return 0;

	size_t len = strlen(p);
	while (len > 0 && (p[len - 1] == ' ' || p[len - 1] == '\t' || p[len - 1] == '\r' || p[len - 1] == '\n'))
		len--;

	if (len == 0 || len > MAX_PATH_LEN)
		return 0;

	if (strstr(p, ".."))
		return 0;

	if (p[0] != '/') {
		if (snprintf(out, outsz, "/data/plugins/%.*s", (int)len, p) >= (int)outsz)
			return 0;
	}
	else {
		if (snprintf(out, outsz, "%.*s", (int)len, p) >= (int)outsz)
			return 0;
	}

	return 1;
}

static int get_or_create_slot(const char* tid) {
	if (!tid || !*tid)
		return -1;

	for (int i = 0; i < g_plugin_count; i++) {
		if (strcmp(g_plugins[i].title_id, tid) == 0)
			return i;
	}

	if (g_plugin_count >= MAX_TITLES)
		return -1;

	int slot = g_plugin_count++;
	memset(&g_plugins[slot], 0, sizeof(g_plugins[slot]));
	strncpy(g_plugins[slot].title_id, tid, MAX_TITLE_ID_LEN);
	g_plugins[slot].title_id[MAX_TITLE_ID_LEN] = '\0';
	return slot;
}

static int register_plugin(int slot, const char* path, int delay_ms, int inject, int restore) {
	if (slot < 0 || slot >= g_plugin_count)
		return 0;

	if (g_plugins[slot].path_count >= MAX_PLUGINS)
		return 0;

	int idx = g_plugins[slot].path_count++;
	strncpy(g_plugins[slot].paths[idx], path, MAX_PATH_LEN);
	g_plugins[slot].paths[idx][MAX_PATH_LEN] = '\0';
	g_plugins[slot].delays[idx] = delay_ms;
	g_plugins[slot].injects[idx] = inject;
	g_plugins[slot].restores[idx] = restore;
	return 1;
}

static void apply_loader_key(const char* key, const char* val) {
	int iv = 0;

	if (strcmp(key, "timeout_s") == 0 && parse_int_value(val, &iv) && iv >= 1 && iv <= 3600)
		g_timeout_s = iv;
	else if (strcmp(key, "scan_existing") == 0 && parse_bool_value(val, &iv))
		g_scan_existing = iv;
	else if (strcmp(key, "default_inject") == 0 && parse_bool_value(val, &iv))
		g_default_inject = iv;
	else if (strcmp(key, "default_restore_sandbox") == 0 && parse_bool_value(val, &iv))
		g_default_restore = iv;
}

static void flush_pending(pending_plugin_t* p) {
	if (!p->active)
		return;

	if (p->title[0] && p->path[0]) {
		char normalized[MAX_PATH_LEN + 1];

		if (normalize_path(p->path, normalized, sizeof(normalized))) {
			int slot = get_or_create_slot(p->title);

			if (slot >= 0) {
				register_plugin(
					slot,
					normalized,
					p->has_delay ? p->delay_ms : 0,
					p->has_inject ? p->inject : g_default_inject,
					p->has_restore ? p->restore : g_default_restore
				);
			}
		}
	}

	memset(p, 0, sizeof(*p));
}

static uint8_t* read_file(const char* path, size_t* outsz) {
	FILE* f = fopen(path, "rb");
	if (!f)
		return NULL;

	if (fseek(f, 0, SEEK_END) != 0) {
		fclose(f);
		return NULL;
	}

	long sz = ftell(f);
	if (sz < 0) {
		fclose(f);
		return NULL;
	}

	if (fseek(f, 0, SEEK_SET) != 0) {
		fclose(f);
		return NULL;
	}

	uint8_t* buf = malloc((size_t)sz + 1);
	if (!buf) {
		fclose(f);
		return NULL;
	}

	size_t rd = fread(buf, 1, (size_t)sz, f);
	fclose(f);

	if (rd != (size_t)sz) {
		free(buf);
		return NULL;
	}

	buf[sz] = 0;
	if (outsz)
		*outsz = (size_t)sz;

	return buf;
}

static char* normalize_config(const uint8_t* in, size_t insz, size_t* outsz) {
	if (!in || insz == 0 || !outsz)
		return NULL;

	char* out = malloc(insz + 1);
	if (!out)
		return NULL;

	size_t o = 0;
	int utf16le = 0;
	int utf16be = 0;
	size_t start = 0;

	if (insz >= 3 && in[0] == 0xEF && in[1] == 0xBB && in[2] == 0xBF) {
		start = 3;
	}
	else if (insz >= 2 && in[0] == 0xFF && in[1] == 0xFE) {
		utf16le = 1;
		start = 2;
	}
	else if (insz >= 2 && in[0] == 0xFE && in[1] == 0xFF) {
		utf16be = 1;
		start = 2;
	}
	else if (insz >= 2 && in[0] != 0 && in[1] == 0) {
		utf16le = 1;
	}
	else if (insz >= 2 && in[0] == 0 && in[1] != 0) {
		utf16be = 1;
	}

	int last_nl = 1;

	if (utf16le || utf16be) {
		for (size_t i = start; i + 1 < insz; i += 2) {
			uint16_t u;

			if (utf16le)
				u = (uint16_t)(in[i] | (in[i + 1] << 8));
			else
				u = (uint16_t)((in[i] << 8) | in[i + 1]);

			if (u == 0)
				continue;

			unsigned char c = 0;
			int is_nl = 0;

			if (u == 0x0D || u == 0x0A) {
				is_nl = 1;
				c = '\n';
			}
			else if (u == 9) {
				c = '\t';
			}
			else if (u >= 32 && u < 127) {
				c = (unsigned char)u;
			}
			else {
				c = '?';
			}

			if (is_nl) {
				if (!last_nl)
					out[o++] = '\n';
				last_nl = 1;
			}
			else {
				out[o++] = (char)c;
				last_nl = 0;
			}
		}
	}
	else {
		for (size_t i = start; i < insz; i++) {
			unsigned char c = in[i];

			if (c == 0)
				continue;

			if (c == '\r' || c == '\n') {
				if (!last_nl)
					out[o++] = '\n';
				last_nl = 1;
			}
			else {
				out[o++] = (char)c;
				last_nl = 0;
			}
		}
	}

	out[o] = '\0';
	*outsz = o;
	return out;
}

static int key_follows(const char* s, size_t i, const char* key) {
	size_t k = strlen(key);

	if (strncmp(s + i, key, k) != 0)
		return 0;

	size_t j = i + k;
	while (s[j] == ' ' || s[j] == '\t')
		j++;

	return s[j] == '=';
}

static char* add_line_breaks(const char* in, size_t* outsz) {
	if (!in || !outsz)
		return NULL;

	size_t len = strlen(in);
	if (len > (SIZE_MAX - 64) / 3)
		return NULL;

	char* out = malloc(len * 3 + 64);
	if (!out)
		return NULL;

	static const char* keys[] = {
		"timeout_s",
		"scan_existing",
		"default_inject",
		"default_restore_sandbox",
		"title",
		"path",
		"delay_ms",
		"inject",
		"restore_sandbox"
	};

	size_t o = 0;
	int inq = 0;
	int incomment = 0;

	for (size_t i = 0; i < len; i++) {
		char c = in[i];

		if (c == '\n') {
			inq = 0;
			incomment = 0;
			out[o++] = c;
			continue;
		}

		if (!inq && !incomment && (c == '#' || c == ';')) {
			incomment = 1;
			out[o++] = c;
			continue;
		}

		if (incomment) {
			out[o++] = c;
			continue;
		}

		if (c == '"') {
			inq = !inq;
			out[o++] = c;
			continue;
		}

		if (!inq) {
			if (c == '[') {
				if (o > 0 && out[o - 1] != '\n' && out[o - 1] != '[')
					out[o++] = '\n';

				out[o++] = c;
				continue;
			}

			if (i == 0 || in[i - 1] == ' ' || in[i - 1] == '\t' || in[i - 1] == '\n' || in[i - 1] == ']') {
				int br = 0;

				for (size_t k = 0; k < sizeof(keys) / sizeof(keys[0]); k++) {
					if (key_follows(in, i, keys[k])) {
						br = 1;
						break;
					}
				}

				if (br && o > 0 && out[o - 1] != '\n')
					out[o++] = '\n';
			}
		}

		out[o++] = c;
	}

	out[o] = '\0';
	*outsz = o;
	return out;
}

static void read_toml(const char* path) {
	size_t rawsz = 0;
	uint8_t* raw = read_file(path, &rawsz);

	if (!raw) {
		return;
	}

	if (rawsz == 0) {
		free(raw);
		return;
	}

	size_t cfgsz = 0;
	char* cfg = normalize_config(raw, rawsz, &cfgsz);
	free(raw);

	if (!cfg) {
		return;
	}

	size_t brsz = 0;
	char* cfg2 = add_line_breaks(cfg, &brsz);

	if (cfg2) {
		free(cfg);
		cfg = cfg2;
		cfgsz = brsz;
	}

	char line[MAX_LINE_LEN];
	char section[64];
	int in_loader = 0;
	const char* p = cfg;

	while (p && *p) {
		const char* nl = strchr(p, '\n');
		size_t len = nl ? (size_t)(nl - p) : strlen(p);

		if (len >= sizeof(line))
			len = sizeof(line) - 1;

		memcpy(line, p, len);
		line[len] = '\0';

		strip_comment(line);
		char* s = trim(line);

		if (!is_blank_or_comment(s)) {
			if (parse_array_table(s, section, sizeof(section))) {
				in_loader = 0;
			}
			else if (parse_table(s, section, sizeof(section))) {
				in_loader = strcmp(section, "loader") == 0;
			}
			else if (in_loader) {
				char* key = NULL;
				char* val = NULL;

				if (split_key_value(s, &key, &val))
					apply_loader_key(key, val);
			}
		}

		if (!nl)
			break;

		p = nl + 1;
	}

	pending_plugin_t pend;
	memset(&pend, 0, sizeof(pend));

	in_loader = 0;
	p = cfg;

	while (p && *p) {
		const char* nl = strchr(p, '\n');
		size_t len = nl ? (size_t)(nl - p) : strlen(p);

		if (len >= sizeof(line))
			len = sizeof(line) - 1;

		memcpy(line, p, len);
		line[len] = '\0';

		strip_comment(line);
		char* s = trim(line);

		if (!is_blank_or_comment(s)) {
			if (parse_array_table(s, section, sizeof(section))) {
				flush_pending(&pend);
				in_loader = 0;

				if (strcmp(section, "plugin") == 0) {
					memset(&pend, 0, sizeof(pend));
					pend.active = 1;
				}
				else {
					memset(&pend, 0, sizeof(pend));
				}
			}
			else if (parse_table(s, section, sizeof(section))) {
				flush_pending(&pend);

				if (strcmp(section, "loader") == 0) {
					in_loader = 1;
					memset(&pend, 0, sizeof(pend));
				}
				else if (strcmp(section, "plugin") == 0) {
					in_loader = 0;
					memset(&pend, 0, sizeof(pend));
					pend.active = 1;
				}
				else {
					in_loader = 0;
					memset(&pend, 0, sizeof(pend));
				}
			}
			else {
				char* key = NULL;
				char* val = NULL;

				if (split_key_value(s, &key, &val)) {
					if (in_loader) {
						apply_loader_key(key, val);
					}
					else if (pend.active) {
						char sv[MAX_PATH_LEN + 1];
						int iv = 0;

						if (strcmp(key, "title") == 0 && parse_string_value(val, sv, sizeof(sv))) {
							strncpy(pend.title, sv, MAX_TITLE_ID_LEN);
							pend.title[MAX_TITLE_ID_LEN] = '\0';
						}
						else if (strcmp(key, "path") == 0 && parse_string_value(val, sv, sizeof(sv))) {
							strncpy(pend.path, sv, MAX_PATH_LEN);
							pend.path[MAX_PATH_LEN] = '\0';
						}
						else if (strcmp(key, "delay_ms") == 0 && parse_int_value(val, &iv) && iv >= 0 && iv <= 3600000) {
							pend.delay_ms = iv;
							pend.has_delay = 1;
						}
						else if (strcmp(key, "inject") == 0 && parse_bool_value(val, &iv)) {
							pend.inject = iv;
							pend.has_inject = 1;
						}
						else if (strcmp(key, "restore_sandbox") == 0 && parse_bool_value(val, &iv)) {
							pend.restore = iv;
							pend.has_restore = 1;
						}
					}
				}
			}
		}

		if (!nl)
			break;

		p = nl + 1;
	}

	flush_pending(&pend);
	free(cfg);
}

static int lock_acquire(void) {
	for (;;) {
		int fd = open(LOCK_PATH, O_WRONLY | O_CREAT | O_EXCL, 0644);
		if (fd >= 0) {
			char buf[32];
			int len = snprintf(buf, sizeof(buf), "%d\n", getpid());

			ssize_t written = write(fd, buf, (size_t)len);
			int saved_errno = errno;
			close(fd);

			if (written == len)
				return 1;

			errno = saved_errno;
			unlink(LOCK_PATH);
			return 0;
		}

		if (errno != EEXIST)
			return 0;

		FILE* f = fopen(LOCK_PATH, "r");
		if (!f)
			continue;

		char buf[32] = { 0 };
		pid_t other = 0;

		if (fgets(buf, sizeof(buf), f))
			other = (pid_t)atoi(buf);

		fclose(f);

		if (other > 1) {
			int alive = pid_alive(other);
			if (alive > 0) {
				return 0;
			}
		}

		if (unlink(LOCK_PATH) != 0 && errno != ENOENT)
			return 0;
	}
}

static void lock_release(void) {
	char mine[32];
	snprintf(mine, sizeof(mine), "%d", getpid());

	FILE* f = fopen(LOCK_PATH, "r");
	if (!f)
		return;

	char buf[32] = { 0 };
	int owns_lock = 0;

	if (fgets(buf, sizeof(buf), f) && strcmp(trim(buf), mine) == 0)
		owns_lock = 1;

	fclose(f);

	if (owns_lock)
		unlink(LOCK_PATH);
}

static void run_plugins(void) {
	pid_t known[MAX_KNOWN_PIDS];
	int known_count = 0;
	g_target_count = 0;
	memset(g_targets, 0, sizeof(g_targets));

	if (!g_scan_existing)
		known_count = get_all_pids(known, MAX_KNOWN_PIDS);

	long start_ms = now_ms();
	const long timeout_ms = (long)g_timeout_s * 1000L;

	for (;;) {
		if (now_ms() - start_ms >= timeout_ms) {
			notify("Timeout");
			break;
		}

		prune_dead_pids(known, &known_count);

		for (int i = 0; i < g_target_count;) {
			if (pid_alive(g_targets[i].pid) == 0) {
				remove_target(i);
				continue;
			}

			i++;
		}

		pid_t cur[MAX_KNOWN_PIDS];
		int cur_count = get_all_pids(cur, MAX_KNOWN_PIDS);

		for (int i = 0; i < cur_count; i++) {
			pid_t pid = cur[i];

			if (pid <= 1 || pid_list_contains(known, known_count, pid))
				continue;

			if (find_target(pid))
				continue;

			app_info_t info;
			memset(&info, 0, sizeof(info));

			if (sceKernelGetAppInfo(pid, &info) != 0 || info.title_id[0] == '\0') {
				pid_list_add(known, &known_count, MAX_KNOWN_PIDS, pid);
				continue;
			}

			plugin_entry_t* entry = find_entry(info.title_id);
			if (!entry || entry->path_count <= 0) {
				pid_list_add(known, &known_count, MAX_KNOWN_PIDS, pid);
				continue;
			}

			target_state_t* target = create_target(pid, info.title_id);
			if (!target) {
				notify("Target table full");
				continue;
			}

			notify("[%s] detected", info.title_id);
		}

		for (int i = 0; i < g_target_count;) {
			target_state_t* target = &g_targets[i];
			plugin_entry_t* entry = find_entry(target->title_id);

			if (!entry) {
				remove_target(i);
				continue;
			}

			long now = now_ms();
			if (now < target->retry_at_ms) {
				i++;
				continue;
			}

			for (int p = 0; p < entry->path_count; p++) {
				if (!entry->injects[p] || target->injected[p])
					continue;

				long ready_at = target->created_ms + (long)entry->delays[p];
				if (!target->started[p]) {
					if (now < ready_at)
						continue;
					target->started[p] = 1;
				}

				const char* path = entry->paths[p];

				if (pid_alive(target->pid) <= 0) {
					break;
				}

				if (access(path, R_OK) != 0) {
					notify("[%s] %s unavailable", entry->title_id, get_filename(path));
					target->retry_at_ms = now_ms() + 1000;
					break;
				}

				if (pt_attach(target->pid) < 0) {
					notify("[%s] attach failed", entry->title_id);
					target->retry_at_ms = now_ms() + 1000;
					break;
				}

				intptr_t ucred = kernel_get_proc_ucred(target->pid);
				ps5_ucred_snapshot_t saved;
				memset(&saved, 0, sizeof(saved));

				if (!ucred || save_creds(ucred, &saved, target->pid) != 0) {
					notify("[%s] credential snapshot failed", entry->title_id);
					pt_detach(target->pid);
					target->retry_at_ms = now_ms() + 1000;
					break;
				}

				if (jb_pid(target->pid, ucred) != 0) {
					notify("[%s] privilege setup failed", entry->title_id);
					restore_creds(ucred, &saved, target->pid);
					pt_detach(target->pid);
					target->retry_at_ms = now_ms() + 1000;
					break;
				}

				int rc = inject_prx(target->pid, path);

				if (entry->restores[p] || rc <= 0) {
					if (restore_creds(ucred, &saved, target->pid) != 0) {
						notify("[%s] credential restore failed", entry->title_id);
					}
				}

				pt_detach(target->pid);

				if (rc > 0) {
					target->injected[p] = 1;
					notify("[%s] %s loaded", entry->title_id, get_filename(path));
				}
				else {
					notify("[%s] %s failed", entry->title_id, get_filename(path));
					target->retry_at_ms = now_ms() + 1000;
					break;
				}
			}

			if (target_all_injected(entry, target)) {
				notify("[%s] complete", entry->title_id);
				pid_list_add(known, &known_count, MAX_KNOWN_PIDS, target->pid);
				remove_target(i);
				continue;
			}

			i++;
		}

		usleep(10000);
	}
}

int main(void) {
	clock_gettime(CLOCK_MONOTONIC, &g_t0);

	signal(SIGSEGV, SIG_DFL);
	signal(SIGBUS, SIG_DFL);

	if (!lock_acquire())
		return 0;

	notify("Starting");

	read_toml(DEFAULT_TOML_PATH);

	if (g_plugin_count == 0) {
		notify("No valid plugins configured");
		lock_release();
		return 0;
	}

	run_plugins();

	notify("Done");

	lock_release();
	return 0;
}