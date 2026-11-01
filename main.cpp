#include <ps5/kernel.h>

#include <dlfcn.h>
#include <elf.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <machine/reg.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iterator>
#include <map>
#include <string>
#include <unordered_set>
#include <vector>

extern "C" {
	int  sceKernelGetProcessName(pid_t pid, char* name);
	int  sceKernelGetAppInfo(pid_t pid, void* info);
	int  sceKernelSendNotificationRequest(int, const void*, size_t, int);
	int  kernel_proc_getpaddr(pid_t pid, intptr_t addr, intptr_t* paddr, size_t* len);
	extern intptr_t KERNEL_ADDRESS_DMAP_BASE;
}

namespace {

	constexpr const char* kConfigPath = "/data/plugins/ploader.toml";
	constexpr const char* kLogPath = "/data/plugins/ploader.log";
	constexpr const char* kLockPath = "/data/plugins/ploader.lock";
	constexpr const char* kPluginDir = "/data/plugins/";

	constexpr uint64_t kAuthidDebugger = 0x4800000000010003ULL;
	constexpr uint64_t kAuthidSystem = 0x4801000000000013ULL;

	constexpr const char* kNidLoadStartModule = "wzvqT4UqKX8";
	constexpr const char* kNidPthreadCreate = "OxhIB8LB-PQ";
	constexpr const char* kNidGetpid = "HoLVWNanBBc";

	constexpr long kScanIntervalMs = 50;
	constexpr long kRetryMs = 50;
	constexpr long kSlowRetryMs = 1000;
	constexpr long kBindRetryMs = 2500;
	constexpr int  kBindPasses = 3;
	constexpr long kImageWaitMs = 5000;
	constexpr long kLoadWaitMs = 30000;
	constexpr long kMainLoadWaitMs = 120000;
	constexpr long kMainRetryMs = 250;
	constexpr long kDepWaitMs = 15000;
	constexpr int  kMaxRefusals = 200;

	constexpr intptr_t kRegionBlock = 0x4000;
	constexpr intptr_t kRegionSize = 0x10000;
	constexpr intptr_t kRegionStub = 0x0100;
	constexpr intptr_t kRegionContext = 0x4000;
	constexpr intptr_t kRegionThread = 0x4800;
	constexpr intptr_t kRegionStackTop = kRegionSize;
	constexpr intptr_t kModulePathOffset = 0x0100;

	constexpr int64_t kPending = INT64_MIN;

	constexpr int kMaxPluginsPerTitle = 16;
	constexpr int kMaxTrackedTargets = 256;
	constexpr int kMaxSeenPids = 1024;

	struct AppInfo {
		uint32_t app_id;
		uint32_t app_type;
		uint64_t unknown1;
		char     title_id[16];
		char     reserved[0x100];
	};
	static_assert(offsetof(AppInfo, title_id) == 16, "unexpected app info layout");

	struct LoadContext {
		uint64_t load_start_module;
		uint64_t module_path;
		int64_t  result;
		int64_t  call_result;
	};
	static_assert(sizeof(LoadContext) == 32, "unexpected load context layout");

	struct RemoteCall {
		intptr_t stub;
		intptr_t stack_top;
		intptr_t function;
		intptr_t result_slot;
		uint64_t args[4];
	};

	struct Credentials {
		intptr_t ucred = 0;
		uid_t    uid = 0;
		uid_t    ruid = 0;
		uid_t    svuid = 0;
		gid_t    rgid = 0;
		gid_t    svgid = 0;
		uint32_t ngroups = 0;
		uint64_t authid = 0;
		uint8_t  caps[16] = {};
		uint8_t  attrs[32] = {};
		intptr_t rootdir = 0;
		intptr_t jaildir = 0;
	};

	enum class LoadResult { Failed, Confirmed, Started, Again };

	enum PluginState { kStatePending = 0, kLoaded = 1, kFailed = 2 };

	struct PluginConfig {
		std::string title;
		std::string path;
		int inject = -1;
		int delay_ms = -1;
		int main_thread = 0;
	};

	struct Options {
		int timeout_s = 60;
		int delay_ms = 1000;
		int debug_log = 0;
		int console_log = 0;
		int expose_data = 0;
	};

	struct ResolvedPlugin {
		std::string path;
		int delay_ms = 0;
		bool main_thread = false;
	};

	struct Target {
		pid_t pid = -1;
		std::string title;
		long detected_ms = 0;
		long ready_ms = -1;
		long next_at_ms = 0;
		int  observed = -1;
		int  load_up = -1;
		int  pthread_up = -1;
		int  refusals = 0;
		long dep_since_ms = 0;
		bool dep_gave_up = false;
		bool data_mounted = false;
		bool data_repaired = false;
		bool mount_fail_notified = false;
		long mount_retry_at_ms = 0;
		int  bind_passes = 0;
		std::vector<std::string> data_mounts;
		std::vector<std::string> dep_missing;
		std::vector<int> state;
	};

	FILE* g_log = nullptr;
	long        g_log_start_ms = 0;
	Options     g_options;
	std::vector<PluginConfig> g_plugins;
	std::string g_warning;
	std::vector<Target> g_targets;

	long g_next_heartbeat_ms = 0;

	long now_ms()
	{
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
	}

	std::string format(const char* fmt, va_list args)
	{
		char buffer[2048];

		vsnprintf(buffer, sizeof(buffer), fmt, args);
		return buffer;
	}

	std::string format(const char* fmt, ...)
	{
		va_list args;

		va_start(args, fmt);
		std::string out = format(fmt, args);
		va_end(args);
		return out;
	}

	void logf(const char* fmt, ...)
	{
		va_list args;

		va_start(args, fmt);
		std::string message = format(fmt, args);
		va_end(args);

		char line[2200];
		if (g_log) {
			snprintf(line, sizeof(line), "[%7ld ms] %s\n", now_ms() - g_log_start_ms, message.c_str());
			fputs(line, g_log);
			fflush(g_log);
		}

		if (g_options.console_log) {
			printf("[%7ld ms] %s\n", now_ms() - g_log_start_ms, message.c_str());
			fflush(stdout);
		}
	}

	void log_open(const char* path)
	{
		if (!g_options.debug_log || g_log)
			return;

		g_log = fopen(path, "a");
		if (g_log_start_ms == 0)
			g_log_start_ms = now_ms();
	}

	void notify(const char* fmt, ...)
	{
		va_list args;
		va_start(args, fmt);
		std::string message = format(fmt, args);
		va_end(args);

		struct {
			char unused[45];
			char text[3075];
		} request = {};

		snprintf(request.text, sizeof(request.text), "[ploader] %s", message.c_str());
		sceKernelSendNotificationRequest(0, &request, sizeof(request), 0);
	}

	void console_out(const char* fmt, ...)
	{
		if (!g_options.console_log)
			return;

		va_list args;
		va_start(args, fmt);
		std::string message = format(fmt, args);
		va_end(args);

		printf("ploader: %s\n", message.c_str());
		fflush(stdout);
	}

	bool iequals(const std::string& a, const std::string& b)
	{
		if (a.size() != b.size())
			return false;

		for (size_t i = 0; i < a.size(); i++) {
			if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i]))
				return false;
		}
		return true;
	}

	std::string trim(const std::string& text)
	{
		size_t begin = 0;
		size_t end = text.size();

		while (begin < end && isspace((unsigned char)text[begin]))
			begin++;
		while (end > begin && isspace((unsigned char)text[end - 1]))
			end--;

		return text.substr(begin, end - begin);
	}

	const char* file_name(const char* path)
	{
		const char* slash = strrchr(path, '/');
		return slash ? slash + 1 : path;
	}

	bool process_is_alive(pid_t pid)
	{
		if (pid <= 1)
			return false;
		if (kill(pid, 0) == 0)
			return true;
		return errno == EPERM;
	}

	int read_app_title_id(pid_t pid, std::string& out)
	{
		AppInfo info = {};

		if (sceKernelGetAppInfo(pid, &info) != 0)
			return -1;

		size_t length = strnlen(info.title_id, sizeof(info.title_id));
		if (length == 0)
			return -1;

		out.assign(info.title_id, length);
		return 0;
	}

	std::string process_name(pid_t pid)
	{
		char name[0x20] = {};

		if (sceKernelGetProcessName(pid, name) != 0)
			return {};
		return name;
	}

	std::vector<pid_t> collect_process_ids()
	{
		int    mib[4] = { 1, 14, 8, 0 };
		size_t size = 0;

		if (sysctl(mib, 4, nullptr, &size, nullptr, 0) < 0)
			return {};

		std::vector<uint8_t> buffer(size > 4096 ? size : 4096);

		if (sysctl(mib, 4, buffer.data(), &size, nullptr, 0) < 0)
			return {};

		std::vector<pid_t> pids;
		uint8_t* begin = buffer.data();
		uint8_t* end = begin + size;

		for (uint8_t* entry = begin; entry + 0x4C <= end;) {
			int length = *(int*)entry;
			if (length < 0x4C || entry + length > end)
				break;

			pid_t pid = *(pid_t*)(entry + 0x48);
			if (pid > 1)
				pids.push_back(pid);

			entry += length;
		}

		return pids;
	}

	void strip_comment(std::string& line)
	{
		char quote = '\0';

		for (size_t i = 0; i < line.size(); i++) {
			char c = line[i];

			if (quote != '\0') {
				if (c == '\\' && quote == '"' && i + 1 < line.size())
					i++;
				else if (c == quote)
					quote = '\0';
				continue;
			}

			if (c == '"' || c == '\'') {
				quote = c;
				continue;
			}

			if ((c == '#' || c == ';') &&
				(i == 0 || line[i - 1] == ' ' || line[i - 1] == '\t')) {
				line.resize(i);
				return;
			}
		}
	}

	bool parse_bool(const std::string& value, int& out)
	{
		static const char* const yes[] = { "1", "true", "yes", "on" };
		static const char* const no[] = { "0", "false", "no", "off" };

		for (const char* word : yes) {
			if (iequals(value, word)) {
				out = 1;
				return true;
			}
		}
		for (const char* word : no) {
			if (iequals(value, word)) {
				out = 0;
				return true;
			}
		}
		return false;
	}

	bool parse_int(const std::string& value, int& out)
	{
		errno = 0;
		char* end = nullptr;
		long parsed = strtol(value.c_str(), &end, 10);

		if (end == value.c_str() || errno == ERANGE)
			return false;

		while (*end == ' ' || *end == '\t')
			end++;
		if (*end != '\0')
			return false;

		out = (int)parsed;
		return true;
	}

	std::string parse_string(const std::string& value)
	{
		if (value.empty())
			return {};

		char quote = value[0];
		if (quote != '"' && quote != '\'')
			return trim(value);

		std::string out;
		for (size_t i = 1; i < value.size(); i++) {
			char c = value[i];

			if (c == quote)
				return out;

			if (c == '\\' && i + 1 < value.size()) {
				char next = value[++i];
				if (next == 'n')
					out.push_back('\n');
				else if (next == 't')
					out.push_back('\t');
				else
					out.push_back(next);
				continue;
			}

			out.push_back(c);
		}

		return {};
	}

	void set_warning(const std::string& warning)
	{
		if (!g_warning.empty())
			g_warning += "; ";
		g_warning += warning;
	}

	std::string normalize_path(const std::string& path)
	{
		if (path.empty() || path.size() > 255 || path.find("..") != std::string::npos)
			return {};
		if (path[0] == '/')
			return path;
		return std::string(kPluginDir) + path;
	}

	void apply_loader_option(const std::string& key, const std::string& value)
	{
		int parsed = 0;

		if (iequals(key, "timeout_s")) {
			if (!parse_int(value, parsed) || parsed < 1 || parsed > 3600)
				set_warning("bad timeout_s value");
			else
				g_options.timeout_s = parsed;
		}
		else if (iequals(key, "debug_log")) {
			if (!parse_bool(value, parsed))
				set_warning("bad debug_log value");
			else
				g_options.debug_log = parsed;
		}
		else if (iequals(key, "console_log")) {
			if (!parse_bool(value, parsed))
				set_warning("bad console_log value");
			else
				g_options.console_log = parsed;
		}
		else if (iequals(key, "delay_ms") || iequals(key, "plugin_delay_ms")) {
			if (!parse_int(value, parsed) || parsed < 0 || parsed > 60000)
				set_warning("bad delay_ms value");
			else
				g_options.delay_ms = parsed;
		}
		else if (iequals(key, "expose_data")) {
			if (!parse_bool(value, parsed))
				set_warning("bad expose_data value");
			else
				g_options.expose_data = parsed;
		}
		else
			set_warning("unknown option " + key);
	}

	void apply_plugin_option(PluginConfig& pending, bool& started,
		const std::string& key, const std::string& value)
	{
		int parsed = 0;

		started = true;

		if (iequals(key, "title") || iequals(key, "title_id")) {
			pending.title = parse_string(value);
			if (pending.title.empty())
				set_warning("bad plugin title");
		}
		else if (iequals(key, "path")) {
			pending.path = parse_string(value);
			if (pending.path.empty())
				set_warning("bad plugin path");
		}
		else if (iequals(key, "inject")) {
			if (!parse_bool(value, parsed))
				set_warning("bad inject value");
			else
				pending.inject = parsed;
		}
		else if (iequals(key, "delay_ms")) {
			if (!parse_int(value, parsed) || parsed < 0 || parsed > 60000)
				set_warning("bad delay_ms value");
			else
				pending.delay_ms = parsed;
		}
		else if (iequals(key, "main_thread")) {
			if (!parse_bool(value, parsed))
				set_warning("bad main_thread value");
			else
				pending.main_thread = parsed;
		}
		else
			set_warning("unknown option " + key);
	}

	void flush_plugin(PluginConfig& pending, bool& started)
	{
		if (!started)
			return;

		PluginConfig done = pending;
		pending = PluginConfig();
		started = false;

		if (done.path.empty()) {
			set_warning("a plugin has no path");
			return;
		}
		if (done.title.empty()) {
			set_warning("plugin " + done.path + " has no title");
			return;
		}

		std::string path = normalize_path(done.path);
		if (path.empty()) {
			set_warning("bad plugin path " + done.path);
			return;
		}

		done.path = path;
		g_plugins.push_back(done);
	}

	bool config_load(const char* path)
	{
		g_options = Options();
		g_plugins.clear();
		g_warning.clear();

		std::ifstream file(path, std::ios::binary);
		if (!file)
			return false;

		std::string text((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

		if (text.size() >= 3 && (uint8_t)text[0] == 0xEF &&
			(uint8_t)text[1] == 0xBB && (uint8_t)text[2] == 0xBF)
			text.erase(0, 3);

		std::string normalized;
		normalized.reserve(text.size());
		for (char c : text) {
			if (c == '\0')
				continue;
			if (c == '\r')
				c = '\n';
			normalized.push_back(c);
		}

		enum Section { kNone, kLoader, kPlugin } section = kNone;
		PluginConfig pending;
		bool pending_started = false;

		size_t cursor = 0;
		while (cursor <= normalized.size()) {
			size_t newline = normalized.find('\n', cursor);
			std::string line = normalized.substr(
				cursor, newline == std::string::npos ? std::string::npos
				: newline - cursor);

			strip_comment(line);
			line = trim(line);

			if (!line.empty()) {
				bool is_header = line.front() == '[';

				if (is_header) {
					flush_plugin(pending, pending_started);

					size_t begin = 1;
					bool array = begin < line.size() && line[begin] == '[';
					if (array)
						begin++;

					size_t end = line.find(']', begin);
					std::string table = end == std::string::npos
						? std::string() : trim(line.substr(begin, end - begin));

					if (iequals(table, "loader"))
						section = kLoader;
					else if (iequals(table, "plugin"))
						section = kPlugin;
					else {
						set_warning("unknown table [" + table + "]");
						section = kNone;
					}
				}
				else {
					size_t equals = std::string::npos;
					char quote = '\0';

					for (size_t i = 0; i < line.size(); i++) {
						char c = line[i];
						if (quote != '\0') {
							if (c == quote)
								quote = '\0';
							continue;
						}
						if (c == '"' || c == '\'') {
							quote = c;
							continue;
						}
						if (c == '=') {
							equals = i;
							break;
						}
					}

					if (equals == std::string::npos)
						set_warning("cannot read line: " + line);
					else {
						std::string key = trim(line.substr(0, equals));
						std::string value = trim(line.substr(equals + 1));

						if (section == kLoader)
							apply_loader_option(key, value);
						else if (section == kPlugin)
							apply_plugin_option(pending, pending_started, key, value);
						else
							set_warning(key + " is outside any table");
					}
				}
			}

			if (newline == std::string::npos)
				break;
			cursor = newline + 1;
		}

		flush_plugin(pending, pending_started);
		return true;
	}

	bool has_enabled_plugins()
	{
		for (const PluginConfig& plugin : g_plugins) {
			if (plugin.inject != 0)
				return true;
		}
		return false;
	}

	std::vector<ResolvedPlugin> collect_plugins(const std::string& title)
	{
		std::vector<ResolvedPlugin> out;

		auto add = [&](const PluginConfig& plugin) {
			if (plugin.inject == 0)
				return;

			for (const ResolvedPlugin& entry : out) {
				if (iequals(entry.path, plugin.path))
					return;
			}
			if ((int)out.size() >= kMaxPluginsPerTitle)
				return;

			ResolvedPlugin entry;
			entry.path = plugin.path;
			entry.delay_ms = plugin.delay_ms < 0 ? g_options.delay_ms : plugin.delay_ms;
			entry.main_thread = plugin.main_thread != 0;
			out.push_back(entry);
		};

		std::vector<const PluginConfig*> wildcards;
		std::vector<const PluginConfig*> titled;

		for (const PluginConfig& plugin : g_plugins) {
			if (plugin.title == "*")
				wildcards.push_back(&plugin);
			else if (iequals(plugin.title, title))
				titled.push_back(&plugin);
		}

		for (const PluginConfig* plugin : wildcards)
			add(*plugin);
		for (const PluginConfig* plugin : titled)
			add(*plugin);

		return out;
	}

	bool target_is_ready(pid_t pid)
	{
		if (process_name(pid) != "eboot.bin")
			return false;
		return kernel_dynlib_mapbase_addr(pid, 0) > 0;
	}

	std::vector<std::string> module_name_candidates(const std::string& path)
	{
		std::string base = file_name(path.c_str());
		std::vector<std::string> candidates = { base, path };

		size_t dot = base.rfind('.');
		if (dot != std::string::npos && dot > 0) {
			std::string stem = base.substr(0, dot);
			std::string extension = base.substr(dot);

			candidates.push_back(stem);
			if (iequals(extension, ".prx"))
				candidates.push_back(stem + ".sprx");
			else if (iequals(extension, ".sprx"))
				candidates.push_back(stem + ".prx");
		}

		std::vector<std::string> names;
		for (const std::string& name : candidates) {
			if (!name.empty() &&
				std::find(names.begin(), names.end(), name) == names.end())
				names.push_back(name);
		}

		return names;
	}

	int find_module_handle(pid_t pid, const std::string& path, uint32_t& out_handle)
	{
		for (const std::string& name : module_name_candidates(path)) {
			uint32_t handle = 0;
			if (kernel_dynlib_handle(pid, name.c_str(), &handle) == 0 && handle != 0) {
				out_handle = handle;
				return 0;
			}
		}
		return -1;
	}

	int named_module_is_mapped(pid_t pid, const char* name)
	{
		uint32_t handle = 0;

		if (find_module_handle(pid, name, handle) != 0)
			return 0;
		return kernel_dynlib_mapbase_addr(pid, handle) > 0;
	}

	int target_observe(pid_t pid)
	{
		int observed = 0;

		if (pid <= 1)
			return 0;

		if (process_name(pid) == "eboot.bin")
			observed |= 1 << 0;
		if (kernel_dynlib_mapbase_addr(pid, 0) > 0)
			observed |= 1 << 1;
		if (named_module_is_mapped(pid, "eboot.bin"))
			observed |= 1 << 2;
		if (named_module_is_mapped(pid, "/app0/eboot.bin"))
			observed |= 1 << 3;
		if (named_module_is_mapped(pid, "/app0/sce_module/libSceFios2.prx"))
			observed |= 1 << 4;
		if (named_module_is_mapped(pid, "libSceNet.sprx"))
			observed |= 1 << 5;

		return observed;
	}

	std::string target_observe_text(int observed)
	{
		return format("name=%d main=%d eboot=%d path=%d app=%d net=%d",
			!!(observed & (1 << 0)), !!(observed & (1 << 1)),
			!!(observed & (1 << 2)), !!(observed & (1 << 3)),
			!!(observed & (1 << 4)), !!(observed & (1 << 5)));
	}

#ifndef DT_NEEDED
#define DT_NEEDED 1
#endif
#ifndef DT_NULL
#define DT_NULL 0
#endif
#ifndef PT_DYNAMIC
#define PT_DYNAMIC 2
#endif
#ifndef PT_DYNLIBDATA
#define PT_DYNLIBDATA 0x61000000
#endif

	constexpr int    kMaxDependencies = 32;
	constexpr size_t kDependencyNameLen = 64;
	constexpr long   kDynlibStringBase = 0x18;

	struct PluginDeps {
		bool                     readable = false;
		std::string              reason;
		std::vector<std::string> declared;
	};

	bool looks_like_module_name(const char* name, size_t length)
	{
		if (length < 5 || length >= kDependencyNameLen)
			return false;

		for (size_t i = 0; i < length; i++) {
			if (name[i] < 0x20 || name[i] > 0x7e)
				return false;
		}

		return strcmp(name + length - 4, ".prx") == 0 || strncmp(name + length - 5, ".sprx", 5) == 0;
	}

	void read_declared_dependencies(FILE* file, PluginDeps& deps)
	{
		auto read_at = [file](long offset, void* out, size_t size) {
			return fseek(file, offset, SEEK_SET) == 0 && fread(out, 1, size, file) == size;
		};

		auto dependency_name_at = [&](long dynlib_offset, uint64_t name_offset, std::string& out) {
			const long bases[] = { dynlib_offset + kDynlibStringBase, dynlib_offset, 0 };

			for (long base : bases) {
				char buffer[kDependencyNameLen];

				if (base < 0 || name_offset > (uint64_t)LONG_MAX)
					continue;
				if (!read_at(base + (long)name_offset, buffer, sizeof(buffer)))
					continue;

				size_t length = strnlen(buffer, sizeof(buffer));
				if (!looks_like_module_name(buffer, length))
					continue;

				out.assign(buffer, length);
				return true;
			}

			return false;
		};

		Elf64_Ehdr header = {};

		if (!read_at(0, &header, sizeof(header))) {
			deps.reason = "cannot read the ELF header";
			return;
		}

		if (memcmp(header.e_ident, "\x7f" "ELF", 4) != 0) {
			deps.reason = "not an ELF module";
			return;
		}

		if (header.e_phentsize != sizeof(Elf64_Phdr) || header.e_phnum == 0 || header.e_phnum > 64) {
			deps.reason = format("unexpected program headers (%u)", header.e_phnum);
			return;
		}

		long   dynamic_offset = -1;
		long   dynlib_offset = -1;
		size_t dynamic_size = 0;

		for (int i = 0; i < header.e_phnum; i++) {
			Elf64_Phdr phdr = {};
			long offset = (long)header.e_phoff + (long)i * sizeof(phdr);

			if (!read_at(offset, &phdr, sizeof(phdr))) {
				deps.reason = "an unreadable program header";
				return;
			}

			if (phdr.p_type == PT_DYNAMIC) {
				dynamic_offset = (long)phdr.p_offset;
				dynamic_size = phdr.p_filesz;
			}
			else if (phdr.p_type == PT_DYNLIBDATA)
				dynlib_offset = (long)phdr.p_offset;
		}

		if (dynamic_offset < 0 || dynlib_offset < 0) {
			deps.reason = "no dynamic table";
			return;
		}

		int needed = 0;

		for (size_t offset = 0; offset + sizeof(Elf64_Dyn) <= dynamic_size;
			offset += sizeof(Elf64_Dyn)) {
			Elf64_Dyn entry = {};

			if (!read_at(dynamic_offset + (long)offset, &entry, sizeof(entry)))
				break;
			if (entry.d_tag == DT_NULL)
				break;
			if (entry.d_tag != DT_NEEDED)
				continue;

			needed++;

			std::string name;
			if (!dependency_name_at(dynlib_offset, entry.d_un.d_val, name))
				continue;
			if (std::find(deps.declared.begin(), deps.declared.end(), name) !=
				deps.declared.end())
				continue;
			if ((int)deps.declared.size() >= kMaxDependencies)
				continue;

			deps.declared.push_back(name);
		}

		if (needed > 0 && deps.declared.empty())
			deps.reason = "declared dependencies could not be named";
	}

	const PluginDeps& plugin_deps(const std::string& path)
	{
		static std::map<std::string, PluginDeps> cache;
		auto cached = cache.find(path);
		if (cached != cache.end())
			return cached->second;

		PluginDeps deps;
		FILE* file = fopen(path.c_str(), "rb");

		if (!file)
			deps.reason = format("cannot open (errno %d)", errno);
		else {
			read_declared_dependencies(file, deps);
			fclose(file);
			deps.readable = deps.reason.empty();
		}

		return cache.emplace(path, deps).first->second;
	}

	bool dependency_is_loaded(pid_t pid, const std::string& name)
	{
		uint32_t handle = 0;
		return find_module_handle(pid, name, handle) == 0;
	}

	int missing_dependencies(pid_t pid, const std::string& path,
		std::vector<std::string>& missing)
	{
		const PluginDeps& deps = plugin_deps(path);

		missing.clear();
		for (const std::string& name : deps.declared) {
			if (!dependency_is_loaded(pid, name))
				missing.push_back(name);
		}
		return (int)missing.size();
	}

	std::string join_names(const std::vector<std::string>& names)
	{
		std::string out;

		for (const std::string& name : names)
			out += std::string(out.empty() ? "" : ", ") + name;
		return out;
	}

	std::string dependencies_text(pid_t pid, const std::string& path)
	{
		const PluginDeps& deps = plugin_deps(path);

		if (!deps.readable)
			return format("deps unreadable (%s)", deps.reason.c_str());
		if (deps.declared.empty())
			return "no deps declared";

		std::vector<std::string> missing;
		missing_dependencies(pid, path, missing);
		int loaded = (int)deps.declared.size() - (int)missing.size();

		if (missing.empty())
			return format("deps %d/%d loaded", loaded, (int)deps.declared.size());
		return format("deps %d/%d loaded, missing %s", loaded,
			(int)deps.declared.size(), join_names(missing).c_str());
	}

	void log_plugin_deps(const std::string& path)
	{
		const PluginDeps& deps = plugin_deps(path);

		if (!deps.readable)
			logf("deps %s: unreadable (%s); injection will not wait for libraries",
				path.c_str(), deps.reason.c_str());
		else if (deps.declared.empty())
			logf("deps %s: none declared", path.c_str());
		else {
			logf("deps %s: %d declared: %s", path.c_str(),
				(int)deps.declared.size(), join_names(deps.declared).c_str());
		}
	}

	int call_ptrace(int request, pid_t pid, caddr_t addr, int data)
	{
		pid_t self = getpid();
		static int warned = 0;

		uint64_t saved = kernel_get_ucred_authid(self);
		if (!saved) {
			if (!warned) {
				warned = 1;
				logf("own authid read as 0 (read failed); using debugger identity");
			}
			saved = kAuthidDebugger;
		}

		kernel_set_ucred_authid(self, kAuthidDebugger);
		int rc = (int)syscall(SYS_ptrace, request, pid, addr, data);
		int saved_errno = errno;
		kernel_set_ucred_authid(self, saved);
		errno = saved_errno;
		return rc;
	}

	int wait_for_stop(pid_t pid, int* status, int timeout_ms)
	{
		for (int waited = 0;; waited += 10) {
			pid_t rc = waitpid(pid, status, WNOHANG);
			if (rc == pid)
				return 1;
			if (rc < 0) {
				if (errno == EINTR)
					continue;
				return -1;
			}
			if (waited >= timeout_ms)
				return 0;
			usleep(10000);
		}
	}

	int remote_attach(pid_t pid)
	{
		if (pid <= 1)
			return -1;

		for (int attempt = 0; attempt < 3; attempt++) {
			if (call_ptrace(PT_ATTACH, pid, nullptr, 0) != 0) {
				int attach_errno = errno;
				logf("attach: PT_ATTACH refused (errno %d) attempt %d", attach_errno,
					attempt + 1);
				if (attach_errno == ESRCH)
					return -1;
				usleep(300000);
				continue;
			}

			int status = 0;
			int stopped = wait_for_stop(pid, &status, 2000);
			int wait_errno = errno;

			if (stopped > 0) {
				struct reg regs;
				if (call_ptrace(PT_GETREGS, pid, (caddr_t)&regs, 0) == 0) {
					logf("attach: stopped (status %#x, signal %d), rip=%#llx rsp=%#llx",
						status, WSTOPSIG(status),
						(unsigned long long)regs.r_rip,
						(unsigned long long)regs.r_rsp);
					return 0;
				}
				logf("attach: stop did not answer registers (status %#x)", status);
			}
			else {
				logf("attach: no stop within 2000 ms (wait=%d status=%#x errno=%d)",
					stopped, status, wait_errno);
			}

			call_ptrace(PT_DETACH, pid, nullptr, 0);

			if (stopped < 0 && wait_errno == ESRCH)
				return -1;
			usleep(300000);
		}

		return -1;
	}

	int remote_detach(pid_t pid)
	{
		int rc = call_ptrace(PT_DETACH, pid, nullptr, 0);
		if (rc != 0)
			logf("detach: PT_DETACH failed (errno %d): title may be stopped", errno);
		return rc;
	}

	int remote_read(pid_t pid, intptr_t src, void* dst, size_t len)
	{
		struct ptrace_io_desc io = {};
		io.piod_op = PIOD_READ_D;
		io.piod_offs = (void*)src;
		io.piod_addr = dst;
		io.piod_len = len;
		return call_ptrace(PT_IO, pid, (caddr_t)&io, 0);
	}

	int remote_write(pid_t pid, const void* src, intptr_t dst, size_t len)
	{
		struct ptrace_io_desc io = {};
		io.piod_op = PIOD_WRITE_D;
		io.piod_offs = (void*)dst;
		io.piod_addr = (void*)src;
		io.piod_len = len;
		return call_ptrace(PT_IO, pid, (caddr_t)&io, 0);
	}

	int remote_read_running(pid_t pid, intptr_t src, void* dst, size_t len)
	{
		uint8_t* out = (uint8_t*)dst;
		size_t done = 0;

		memset(dst, 0, len);

		while (done < len) {
			intptr_t paddr = 0;
			size_t chunk = 0;

			if (kernel_proc_getpaddr(pid, src + (intptr_t)done, &paddr, &chunk) != 0)
				break;
			if (chunk > len - done)
				chunk = len - done;
			if (chunk == 0)
				break;
			if (kernel_copyout(KERNEL_ADDRESS_DMAP_BASE + paddr, out + done,
				chunk) != 0)
				break;

			done += chunk;
		}

		if (done == len)
			return 0;

		if (remote_attach(pid) != 0)
			return -1;

		int rc = remote_read(pid, src, dst, len);
		remote_detach(pid);
		if (rc != 0)
			memset(dst, 0, len);
		return rc;
	}

	intptr_t remote_resolve_nid(pid_t pid, const char* nid)
	{
		intptr_t addr = kernel_dynlib_resolve(pid, 0x1, nid);
		return addr ? addr : kernel_dynlib_resolve(pid, 0x2001, nid);
	}

	bool loader_is_up(pid_t pid, intptr_t& load_fn, intptr_t& pthread_fn)
	{
		load_fn = remote_resolve_nid(pid, kNidLoadStartModule);
		pthread_fn = remote_resolve_nid(pid, kNidPthreadCreate);
		return load_fn != 0 && pthread_fn != 0;
	}

	uintptr_t private_entry_stack(uintptr_t interrupted_rsp)
	{
		return (interrupted_rsp & ~(uintptr_t)0xf) - (uintptr_t)0x108;
	}

	int step_until_return(pid_t pid, struct reg* live, uintptr_t entry_rsp)
	{
		long started = now_ms();

		while ((uintptr_t)live->r_rsp <= entry_rsp) {
			if (now_ms() - started > 5000)
				return -1;

			if (call_ptrace(PT_STEP, pid, (caddr_t)1, 0) != 0)
				return -1;

			int status = 0;
			for (;;) {
				pid_t waited = waitpid(pid, &status, WNOHANG);
				if (waited == pid)
					break;
				if (waited < 0)
					return -1;
				if (now_ms() - started > 5000)
					return -1;
				usleep(1000);
			}

			if (!WIFSTOPPED(status))
				return -1;

			if (call_ptrace(PT_GETREGS, pid, (caddr_t)live, 0) != 0)
				return -1;
		}
		return 0;
	}

	long remote_syscall(pid_t pid, int sysno, uint64_t arg1, uint64_t arg2,
		uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6)
	{
		intptr_t stub = remote_resolve_nid(pid, kNidGetpid);
		if (!stub)
			return -1;

		struct reg saved;
		if (call_ptrace(PT_GETREGS, pid, (caddr_t)&saved, 0) != 0)
			return -1;

		struct reg live = saved;
		live.r_rip = stub + 0xa;
		live.r_rsp = private_entry_stack(saved.r_rsp);
		live.r_rax = (uint64_t)sysno;
		live.r_rdi = arg1;
		live.r_rsi = arg2;
		live.r_rdx = arg3;
		live.r_r10 = arg4;
		live.r_r8 = arg5;
		live.r_r9 = arg6;

		if (call_ptrace(PT_SETREGS, pid, (caddr_t)&live, 0) != 0) {
			call_ptrace(PT_SETREGS, pid, (caddr_t)&saved, 0);
			return -1;
		}

		if (step_until_return(pid, &live, (uintptr_t)live.r_rsp) != 0) {
			call_ptrace(PT_SETREGS, pid, (caddr_t)&saved, 0);
			return -1;
		}

		long result = (long)live.r_rax;
		call_ptrace(PT_SETREGS, pid, (caddr_t)&saved, 0);
		return result;
	}

	bool valid_mapping(intptr_t page, bool aligned = false)
	{
		if (page < 0x10000 || page >= (intptr_t)0x0000800000000000LL)
			return false;
		return !aligned || (page & (kRegionBlock - 1)) == 0;
	}

	int remote_access(pid_t pid, const std::string& path, int& code)
	{
		code = 0;

		if (pid <= 1 || path.empty())
			return -1;

		if (remote_attach(pid) != 0) {
			code = EIO;
			return -1;
		}

		constexpr size_t kProbePage = 0x1000;
		intptr_t page = (intptr_t)remote_syscall(pid, SYS_mmap, 0, kProbePage,
			PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
		int rc = -1;

		if (valid_mapping(page)) {
			if (remote_write(pid, path.c_str(), page, path.size() + 1) == 0) {
				long result = remote_syscall(pid, SYS_access, (uint64_t)page,
					R_OK, 0, 0, 0, 0);
				rc = (int)result;
				code = rc;
			}
			remote_syscall(pid, SYS_munmap, (uint64_t)page, kProbePage, 0, 0, 0, 0);
		}
		else
			code = ENOMEM;

		remote_detach(pid);
		return rc;
	}

	void remote_release_region(pid_t pid, intptr_t region)
	{
		if (region)
			remote_syscall(pid, SYS_munmap, (uint64_t)region, kRegionSize,
				0, 0, 0, 0);
		remote_detach(pid);
	}

	intptr_t remote_new_region(pid_t pid)
	{
		intptr_t region = (intptr_t)remote_syscall(pid, SYS_mmap, 0, kRegionSize,
			PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (valid_mapping(region, true))
			return region;

		logf("  remote mmap returned %#lx", (unsigned long)region);
		remote_release_region(pid, region);
		return 0;
	}

	constexpr int kStubStackTopOffset = 0x02;
	constexpr int kStubArg1Offset = 0x2f;
	constexpr int kStubArg2Offset = 0x39;
	constexpr int kStubArg3Offset = 0x43;
	constexpr int kStubArg4Offset = 0x4d;
	constexpr int kStubFunctionOffset = 0x5d;
	constexpr int kStubResultOffset = 0x69;
	constexpr int kStubSavedRspOffset = 0x91;
	constexpr int kStubSavedRipOffset = 0x9f;
	constexpr int kCallStubSize = 0xa7;

	const uint8_t kCallStub[] = {
		0x48, 0xbc, 0, 0, 0, 0, 0, 0, 0, 0,
		0x9c,
		0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57,
		0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,
		0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
		0x48, 0x89, 0xe5,
		0x48, 0x83, 0xe4, 0xf0,
		0x48, 0x83, 0xec, 0x20,
		0x48, 0xbf, 0, 0, 0, 0, 0, 0, 0, 0,
		0x48, 0xbe, 0, 0, 0, 0, 0, 0, 0, 0,
		0x48, 0xba, 0, 0, 0, 0, 0, 0, 0, 0,
		0x48, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0,
		0x45, 0x31, 0xc0,
		0x45, 0x31, 0xc9,
		0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0,
		0xff, 0xd0,
		0x48, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0,
		0x48, 0x89, 0x01,
		0x48, 0x89, 0xec,
		0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c,
		0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58,
		0x5f, 0x5e, 0x5d, 0x5b, 0x5a, 0x59, 0x58,
		0x9d,
		0x48, 0xbc, 0, 0, 0, 0, 0, 0, 0, 0,
		0xff, 0x25, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
	};
	static_assert(sizeof(kCallStub) == kCallStubSize, "call stub changed shape");

	const uint8_t kLoadThreadStub[] = {
		0x55,
		0x48, 0x89, 0xe5,
		0x48, 0x83, 0xe4, 0xf0,
		0x48, 0x83, 0xec, 0x20,
		0x48, 0x89, 0x7c, 0x24, 0x10,
		0x48, 0x8b, 0x07,
		0x48, 0x8b, 0x7f, 0x08,
		0x31, 0xf6,
		0x31, 0xd2,
		0x31, 0xc9,
		0x45, 0x31, 0xc0,
		0x45, 0x31, 0xc9,
		0xff, 0xd0,
		0x48, 0x8b, 0x54, 0x24, 0x10,
		0x48, 0x89, 0x42, 0x10,
		0xc9,
		0xc3,
	};

	const uint8_t kMainCallStub[] = {
		0x55,
		0x48, 0x89, 0xe5,
		0x48, 0x83, 0xe4, 0xf0,
		0x48, 0x83, 0xec, 0x28,
		0x49, 0xbf,
		0, 0, 0, 0, 0, 0, 0, 0,
		0x31, 0xf6,
		0x31, 0xd2,
		0x31, 0xc9,
		0x45, 0x31, 0xc0,
		0x45, 0x31, 0xc9,
		0x41, 0xff, 0xd7,
		0x48, 0x89, 0xec,
		0x5d,
		0xcc,
	};
	constexpr size_t kMainCallFnOffset = 14;

	int remote_start_call(pid_t pid, const RemoteCall& call)
	{
		static const int arg_offsets[4] = { kStubArg1Offset, kStubArg2Offset, kStubArg3Offset, kStubArg4Offset };

		if (pid <= 1 || !call.stub || !call.stack_top || !call.function || !call.result_slot)
			return -1;

		struct reg interrupted;
		if (call_ptrace(PT_GETREGS, pid, (caddr_t)&interrupted, 0) != 0)
			return -1;

		uint8_t code[kCallStubSize];
		uint64_t value = (uint64_t)call.stack_top;

		memcpy(code, kCallStub, sizeof(code));
		memcpy(code + kStubStackTopOffset, &value, sizeof(value));
		for (int i = 0; i < 4; i++) {
			value = call.args[i];
			memcpy(code + arg_offsets[i], &value, sizeof(value));
		}
		value = (uint64_t)call.function;
		memcpy(code + kStubFunctionOffset, &value, sizeof(value));
		value = (uint64_t)call.result_slot;
		memcpy(code + kStubResultOffset, &value, sizeof(value));
		value = (uint64_t)interrupted.r_rsp;
		memcpy(code + kStubSavedRspOffset, &value, sizeof(value));
		value = (uint64_t)interrupted.r_rip;
		memcpy(code + kStubSavedRipOffset, &value, sizeof(value));

		if (remote_write(pid, code, call.stub, sizeof(code)) != 0) {
			logf("  arm: writing the call stub failed");
			return -1;
		}

		if (kernel_mprotect(pid, call.stub & ~(intptr_t)(kRegionBlock - 1),
			kRegionBlock, PROT_READ | PROT_EXEC) != 0) {
			logf("  arm: mprotect failed");
			return -1;
		}

		struct reg armed = interrupted;
		armed.r_rip = (uint64_t)call.stub;
		if (call_ptrace(PT_SETREGS, pid, (caddr_t)&armed, 0) != 0) {
			logf("  arm: setting rip failed");
			return -1;
		}

		logf("arm: thread was at rip=%#llx rsp=%#llx", (unsigned long long)interrupted.r_rip, (unsigned long long)interrupted.r_rsp);
		return 0;
	}

	bool capture_credentials(pid_t pid, Credentials& out)
	{
		if (pid <= 1 || kernel_get_proc(pid) == 0)
			return false;

		out = Credentials();
		out.ucred = kernel_get_proc_ucred(pid);
		out.uid = kernel_get_ucred_uid(pid);
		out.ruid = kernel_get_ucred_ruid(pid);
		out.svuid = kernel_get_ucred_svuid(pid);
		out.rgid = kernel_get_ucred_rgid(pid);
		out.svgid = kernel_get_ucred_svgid(pid);
		out.authid = kernel_get_ucred_authid(pid);

		if (!out.ucred || !out.authid)
			return false;

		if (kernel_copyout(out.ucred + 0x10, &out.ngroups, sizeof(out.ngroups)) < 0)
			return false;
		if (kernel_get_ucred_caps(pid, out.caps) < 0)
			return false;
		if (kernel_get_ucred_attrs(pid, out.attrs) < 0)
			return false;

		out.rootdir = kernel_get_proc_rootdir(pid);
		out.jaildir = kernel_get_proc_jaildir(pid);
		return out.rootdir && out.jaildir;
	}

	bool grant_ucred(pid_t pid)
	{
		static const uint8_t full_caps[16] = {
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		};

		if (pid <= 1 || kernel_get_proc(pid) == 0)
			return false;

		if (kernel_set_ucred_uid(pid, 0) != 0 ||
			kernel_set_ucred_ruid(pid, 0) != 0 ||
			kernel_set_ucred_svuid(pid, 0) != 0 ||
			kernel_set_ucred_rgid(pid, 0) != 0 ||
			kernel_set_ucred_svgid(pid, 0) != 0 ||
			kernel_set_ucred_caps(pid, full_caps) != 0)
			return false;

		uint8_t attrs[32] = {};
		if (kernel_get_ucred_attrs(pid, attrs) != 0)
			return false;
		attrs[3] |= 0x80;
		return kernel_set_ucred_attrs(pid, attrs) == 0;
	}

	bool grant_sandbox(pid_t pid)
	{
		intptr_t root = kernel_get_root_vnode();
		if (!root)
			return false;

		return kernel_set_proc_rootdir(pid, root) == 0 &&
			kernel_set_proc_jaildir(pid, root) == 0;
	}

	bool restore_credentials(pid_t pid, const Credentials& creds)
	{
		if (pid <= 1 || !creds.ucred)
			return false;

		if (kernel_set_ucred_uid(pid, creds.uid) != 0 ||
			kernel_set_ucred_ruid(pid, creds.ruid) != 0 ||
			kernel_set_ucred_svuid(pid, creds.svuid) != 0 ||
			kernel_set_ucred_rgid(pid, creds.rgid) != 0 ||
			kernel_set_ucred_svgid(pid, creds.svgid) != 0 ||
			kernel_set_ucred_authid(pid, creds.authid) != 0 ||
			kernel_set_ucred_caps(pid, creds.caps) != 0 ||
			kernel_set_ucred_attrs(pid, creds.attrs) != 0)
			return false;

		if (kernel_set_proc_rootdir(pid, creds.rootdir) != 0 ||
			kernel_set_proc_jaildir(pid, creds.jaildir) != 0)
			return false;

		kernel_copyin(&creds.ngroups, creds.ucred + 0x10, sizeof(creds.ngroups));
		return true;
	}

	int mount_nullfs(const char* source, const char* target)
	{
		const char* const values[] = {
			"fstype", "nullfs", "from", source, "fspath", target
		};

		struct iovec iov[6] = {};
		for (int i = 0; i < 6; i++)
			iov[i] = { (void*)values[i], strlen(values[i]) + 1 };

		return nmount(iov, 6, 0);
	}

	constexpr int kDataTreeDepth = 8;

	struct TreeWidenStats {
		int files = 0;
		int dirs = 0;
		int chmod_fail = 0;
		int chown_fail = 0;
	};

	bool has_module_extension(const char* name)
	{
		size_t length = strlen(name);

		return (length > 4 && iequals(name + length - 4, ".prx")) ||
			(length > 5 && iequals(name + length - 5, ".sprx")) ||
			(length > 4 && iequals(name + length - 4, ".elf"));
	}

	void widen_tree_to_title(const char* dir, int depth, uid_t owner,
		gid_t group, bool change_owner, TreeWidenStats& stats)
	{
		DIR* d = opendir(dir);
		if (!d)
			return;

		struct dirent* ent;
		while ((ent = readdir(d))) {
			const char* name = ent->d_name;
			if (name[0] == '.' && (!name[1] ||
				(name[1] == '.' && !name[2])))
				continue;

			std::string path = std::string(dir) + "/" + name;

			struct stat st;
			if (lstat(path.c_str(), &st) != 0)
				continue;

			if (S_ISDIR(st.st_mode)) {
				if (chmod(path.c_str(), 0777) != 0)
					stats.chmod_fail++;
				else
					stats.dirs++;

				if (change_owner && lchown(path.c_str(), owner, group) != 0)
					stats.chown_fail++;

				if (depth < kDataTreeDepth)
					widen_tree_to_title(path.c_str(), depth + 1, owner, group,
						change_owner, stats);
			}
			else if (S_ISREG(st.st_mode)) {
				mode_t mode = has_module_extension(name) ?
					0777 : (0666 | (st.st_mode & 0111));

				if (chmod(path.c_str(), mode) != 0)
					stats.chmod_fail++;
				else
					stats.files++;

				if (change_owner && lchown(path.c_str(), owner, group) != 0)
					stats.chown_fail++;
			}
		}
		closedir(d);
	}

	void repair_data_tree(uid_t owner, gid_t group)
	{
		TreeWidenStats stats;

		widen_tree_to_title("/data", 0, owner, group, true, stats);
		logf("bind: relaxed %d file(s) and %d dir(s) below /data "
			"(%d chmod fails, %d chown fails)", stats.files, stats.dirs,
			stats.chmod_fail, stats.chown_fail);
	}

	void repair_data_tree_as_system(uid_t owner, gid_t group)
	{
		Credentials self;
		bool captured = capture_credentials(getpid(), self);
		uint64_t saved_authid = captured ? self.authid :
			kernel_get_ucred_authid(getpid());

		int authid_rc = kernel_set_ucred_authid(getpid(), kAuthidSystem);
		bool elevated = authid_rc == 0 && grant_ucred(getpid());

		if (elevated)
			repair_data_tree(owner, group);
		else
			logf("bind: cannot elevate own privileges for chmod/chown "
				"(authidrc %d, errno %d)", authid_rc, errno);

		if (captured)
			restore_credentials(getpid(), self);
		else if (saved_authid)
			kernel_set_ucred_authid(getpid(), saved_authid);
	}

	void repair_target_data(pid_t pid)
	{
		uid_t owner = kernel_get_ucred_uid(pid);
		gid_t group = kernel_get_ucred_rgid(pid);

		if (owner == (uid_t)-1)
			owner = getuid();
		if (group == (gid_t)-1)
			group = getgid();

		repair_data_tree_as_system(owner, group);
	}

	std::string find_sandbox_root(const std::string& title, pid_t pid)
	{
		char link[PATH_MAX];
		char proc_path[64];
		snprintf(proc_path, sizeof(proc_path), "/proc/%d/root", (int)pid);

		ssize_t len = readlink(proc_path, link, sizeof(link) - 1);
		if (len > 0) {
			link[len] = '\0';
			std::string path(link);
			std::string needle = "/mnt/sandbox/" + title + "_";
			if (path.find(needle) == 0)
				return path;
		}

		std::string prefix = title + "_";
		std::string fallback;
		DIR* d = opendir("/mnt/sandbox");

		if (!d)
			return {};

		struct dirent* ent;
		while ((ent = readdir(d))) {
			std::string name = ent->d_name;
			if (name.compare(0, prefix.size(), prefix) != 0)
				continue;

			std::string base = "/mnt/sandbox/" + name;
			std::string eboot = base + "/app0/eboot.bin";

			struct stat st;
			if (stat(eboot.c_str(), &st) == 0) {
				closedir(d);
				return base;
			}

			if (fallback.empty() && stat(base.c_str(), &st) == 0 &&
				S_ISDIR(st.st_mode))
				fallback = base;
		}

		closedir(d);
		return fallback;
	}

	bool mount_system_data(pid_t pid, const std::string& title,
		std::vector<std::string>& mounts)
	{
		std::string root = find_sandbox_root(title, pid);
		if (root.empty()) {
			logf("bind: sandbox root for %s not found", title.c_str());
			return false;
		}

		std::string mount_point = root + "/data";

		Credentials self;
		bool captured = capture_credentials(getpid(), self);

		uint64_t saved_authid = captured ? self.authid :
			kernel_get_ucred_authid(getpid());

		int authid_rc = kernel_set_ucred_authid(getpid(), kAuthidSystem);
		bool elevated = authid_rc == 0 && grant_ucred(getpid());

		if (!elevated) {
			logf("bind: cannot elevate own privileges (authidrc %d, errno %d)",
				authid_rc, errno);
		}

		if (mkdir(mount_point.c_str(), 0777) != 0 && errno != EEXIST) {
			logf("bind: mkdir %s: %s", mount_point.c_str(), strerror(errno));
			if (captured)
				restore_credentials(getpid(), self);
			else if (saved_authid)
				kernel_set_ucred_authid(getpid(), saved_authid);
			return false;
		}

		chmod(mount_point.c_str(), 0777);

		unmount(mount_point.c_str(), MNT_FORCE);

		errno = 0;
		int rc = mount_nullfs("/data", mount_point.c_str());
		int mount_errno = errno;

		if (captured)
			restore_credentials(getpid(), self);
		else if (saved_authid)
			kernel_set_ucred_authid(getpid(), saved_authid);

		if (rc != 0) {
			logf("bind: nmount /data -> %s: %s (errno %d)",
				mount_point.c_str(), strerror(mount_errno), mount_errno);
			return false;
		}

		mounts.push_back(mount_point);
		logf("bind: /data mounted at %s; the game's own root/sandbox is "
			"untouched (save stays intact)", mount_point.c_str());
		return true;
	}

	void release_target_data_mount(Target& target)
	{
		if (target.data_mounts.empty())
			return;

		for (const std::string& mount : target.data_mounts) {
			if (unmount(mount.c_str(), MNT_FORCE) == 0) {
				logf("[%s] unmounted %s", target.title.c_str(), mount.c_str());
				rmdir(mount.c_str());
			}
		}
		target.data_mounts.clear();
		target.data_mounted = false;
	}

	LoadResult classify_load_result(long result)
	{
		uint32_t code = (uint32_t)result;

		if ((int32_t)code > 0)
			return LoadResult::Confirmed;

		if (code == 0x80020016) {
			logf("  load refused with %#x (EINVAL): the title is not ready yet",
				code);
			return LoadResult::Again;
		}

		logf("  load refused with %#x: an error from the module loader", code);
		return LoadResult::Failed;
	}

	LoadResult poll_load(pid_t pid, intptr_t context_page,
		const std::string& path)
	{
		long started = now_ms();

		for (;;) {
			if (!process_is_alive(pid)) {
				uint32_t handle = 0;
				if (find_module_handle(pid, path, handle) == 0)
					return LoadResult::Confirmed;
				logf("  target died before publishing a result");
				return LoadResult::Failed;
			}

			LoadContext context = {};
			if (remote_read_running(pid, context_page, &context,
				sizeof(context)) == 0) {
				if (context.call_result != kPending && context.call_result != 0) {
					logf("  pthread_create failed in the target with %lld",
						(long long)context.call_result);
					return LoadResult::Failed;
				}

				if (context.result != kPending) {
					long result = (long)context.result;
					logf("  load returned %ld (%#x) after %ld ms", result,
						(unsigned)result, now_ms() - started);
					return classify_load_result(result);
				}
			}

			long elapsed = now_ms() - started;
			if (elapsed > kLoadWaitMs) {
				uint32_t handle = 0;
				if (find_module_handle(pid, path, handle) == 0) {
					logf("  no result published, but the module is mapped");
					return LoadResult::Confirmed;
				}
				logf("  still starting after %ld ms", elapsed);
				return LoadResult::Started;
			}

			usleep(50000);
		}
	}

	int remote_call_main(pid_t pid, intptr_t stub, intptr_t path, long timeout_ms,
		long& result)
	{
		struct reg saved;
		if (call_ptrace(PT_GETREGS, pid, (caddr_t)&saved, 0) != 0)
			return -1;

		struct reg live = saved;
		live.r_rip = (uint64_t)stub;
		live.r_rdi = (uint64_t)path;

		if (call_ptrace(PT_SETREGS, pid, (caddr_t)&live, 0) != 0)
			return -1;

		logf("  main: hijacking rip=%#llx with rdi=%#llx",
			(unsigned long long)saved.r_rip, (unsigned long long)path);

		if (call_ptrace(PT_CONTINUE, pid, (caddr_t)1, 0) != 0) {
			call_ptrace(PT_SETREGS, pid, (caddr_t)&saved, 0);
			return -1;
		}

		int status = 0;
		int stopped = wait_for_stop(pid, &status, (int)timeout_ms);
		if (stopped <= 0 || !WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
			logf("  main: no SIGTRAP within %ld ms (wait=%d status=%#x)",
				timeout_ms, stopped, status);
			call_ptrace(PT_SETREGS, pid, (caddr_t)&saved, 0);
			return -1;
		}

		struct reg done;
		if (call_ptrace(PT_GETREGS, pid, (caddr_t)&done, 0) != 0) {
			call_ptrace(PT_SETREGS, pid, (caddr_t)&saved, 0);
			return -1;
		}

		result = (long)done.r_rax;
		call_ptrace(PT_SETREGS, pid, (caddr_t)&saved, 0);
		return 0;
	}

	LoadResult load_plugin_main(pid_t pid, const std::string& path)
	{
		logf("load %s into pid %d (main thread)", path.c_str(), pid);

		intptr_t load_fn = remote_resolve_nid(pid, kNidLoadStartModule);
		if (!load_fn) {
			logf("  the title's loader is not up yet (load=0)");
			return LoadResult::Again;
		}

		if (remote_attach(pid) != 0) {
			logf("  the title would not be paused at this instant");
			return LoadResult::Again;
		}

		intptr_t region = (intptr_t)remote_syscall(pid, SYS_mmap, 0, kRegionSize,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS,
			-1, 0);
		if (!valid_mapping(region, true)) {
			logf("  remote mmap returned %#lx", (unsigned long)region);
			remote_detach(pid);
			return LoadResult::Failed;
		}

		intptr_t stub = region + kRegionStub;
		intptr_t path_addr = region + kRegionContext + kModulePathOffset;

		uint8_t code[sizeof(kMainCallStub)];
		uint64_t value = (uint64_t)load_fn;

		memcpy(code, kMainCallStub, sizeof(code));
		memcpy(code + kMainCallFnOffset, &value, sizeof(value));

		bool written = remote_write(pid, code, stub, sizeof(code)) == 0 &&
			remote_write(pid, path.c_str(), path_addr,
				path.size() + 1) == 0;
		if (!written) {
			logf("  writing the main-call stub failed");
			remote_syscall(pid, SYS_munmap, (uint64_t)region, kRegionSize, 0, 0, 0, 0);
			remote_detach(pid);
			return LoadResult::Failed;
		}

		if (kernel_mprotect(pid, region, kRegionBlock,
			PROT_READ | PROT_EXEC) != 0) {
			logf("  mprotect on the main-call stub failed");
			remote_syscall(pid, SYS_munmap, (uint64_t)region, kRegionSize, 0, 0, 0, 0);
			remote_detach(pid);
			return LoadResult::Failed;
		}

		long result = 0;
		if (remote_call_main(pid, stub, path_addr, kMainLoadWaitMs, result) != 0) {
			logf("  the main-thread load did not return");
			remote_syscall(pid, SYS_munmap, (uint64_t)region, kRegionSize, 0, 0, 0, 0);
			remote_detach(pid);
			return LoadResult::Started;
		}

		logf("  load returned %ld (%#x) on the main thread", result,
			(unsigned)result);

		remote_syscall(pid, SYS_munmap, (uint64_t)region, kRegionSize, 0, 0, 0, 0);
		remote_detach(pid);

		return classify_load_result(result);
	}

	LoadResult load_plugin(pid_t pid, const std::string& path, bool main_thread)
	{
		if (main_thread)
			return load_plugin_main(pid, path);

		logf("load %s into pid %d (remote thread)", path.c_str(), pid);

		intptr_t load_fn = 0;
		intptr_t pthread_fn = 0;
		if (!loader_is_up(pid, load_fn, pthread_fn)) {
			logf("  the title's loader is not up yet (load=%#lx pthread=%#lx)",
				(unsigned long)load_fn, (unsigned long)pthread_fn);
			return LoadResult::Again;
		}

		if (remote_attach(pid) != 0) {
			logf("  the title would not be paused at this instant");
			return LoadResult::Again;
		}

		intptr_t region = remote_new_region(pid);
		if (!region)
			return LoadResult::Failed;

		intptr_t context_page = region + kRegionContext;

		LoadContext context = {};
		context.load_start_module = (uint64_t)load_fn;
		context.module_path = (uint64_t)(context_page + kModulePathOffset);
		context.result = kPending;
		context.call_result = kPending;

		bool written = remote_write(pid, &context, context_page, sizeof(context)) == 0 &&
			remote_write(pid, path.c_str(),
				(intptr_t)context.module_path,
				path.size() + 1) == 0 &&
			remote_write(pid, kLoadThreadStub, region,
				sizeof(kLoadThreadStub)) == 0;

		if (!written) {
			logf("  writing the load context failed");
			remote_release_region(pid, region);
			return LoadResult::Failed;
		}

		RemoteCall call = {};
		call.stub = region + kRegionStub;
		call.stack_top = region + kRegionStackTop;
		call.function = pthread_fn;
		call.result_slot = context_page + offsetof(LoadContext, call_result);
		call.args[0] = (uint64_t)(region + kRegionThread);
		call.args[1] = 0;
		call.args[2] = (uint64_t)region;
		call.args[3] = (uint64_t)context_page;

		logf("  region %#lx, context %#lx, path \"%s\"",
			(unsigned long)region, (unsigned long)context_page, path.c_str());

		if (remote_start_call(pid, call) != 0) {
			logf("  arming the loader thread failed");
			remote_release_region(pid, region);
			return LoadResult::Failed;
		}

		remote_detach(pid);
		logf("  loader thread armed; the title runs while the plugin starts");

		LoadResult result = poll_load(pid, context_page, path);

		uint32_t handle = 0;
		if (result == LoadResult::Confirmed &&
			find_module_handle(pid, path, handle) == 0) {
			logf("  module check: handle %u, mapbase=%#lx entry=%#lx init=%#lx "
				"fini=%#lx", handle,
				(unsigned long)kernel_dynlib_mapbase_addr(pid, handle),
				(unsigned long)kernel_dynlib_entry_addr(pid, handle),
				(unsigned long)kernel_dynlib_init_addr(pid, handle),
				(unsigned long)kernel_dynlib_fini_addr(pid, handle));
		}
		else if (result == LoadResult::Confirmed)
			logf("  the load reported a handle but the module table does not list it");

		return result;
	}

	Target* find_target(pid_t pid)
	{
		for (Target& target : g_targets) {
			if (target.pid == pid)
				return &target;
		}
		return nullptr;
	}

	void seen_insert(std::unordered_set<pid_t>& seen, pid_t pid)
	{
		if ((int)seen.size() >= kMaxSeenPids)
			seen.erase(seen.begin());
		seen.insert(pid);
	}

	void add_target(pid_t pid, const std::string& title)
	{
		if ((int)g_targets.size() >= kMaxTrackedTargets)
			return;

		Target target;
		target.pid = pid;
		target.title = title;
		target.detected_ms = now_ms();
		target.next_at_ms = 0;
		target.state.assign(collect_plugins(title).size(), kStatePending);
		g_targets.push_back(target);

		logf("[%s] pid %d detected at +%ld ms (process \"%s\", main=%#lx)",
			title.c_str(), pid, target.detected_ms - g_log_start_ms,
			process_name(pid).c_str(),
			(unsigned long)kernel_dynlib_mapbase_addr(pid, 0));
		if (g_options.debug_log)
			notify("[%s] detected", title.c_str());
	}

	void drop_dead_targets()
	{
		g_targets.erase(std::remove_if(g_targets.begin(), g_targets.end(),
			[](Target& target) {
				bool alive = process_is_alive(target.pid);
				if (!alive) {
					logf("[%s] pid %d is gone",
						target.title.c_str(),
						target.pid);
					release_target_data_mount(target);
				}
				return !alive;
			}),
			g_targets.end());
	}

	pid_t find_app_pid(int app_id)
	{
		for (pid_t pid : collect_process_ids()) {
			AppInfo info = {};
			if (sceKernelGetAppInfo(pid, &info) == 0 && (int)info.app_id == app_id)
				return pid;
		}
		return -1;
	}

	using get_running_big_app_fn = int (*)();
	using get_app_title_id_fn = int (*)(int, char*);

	auto& resolve_system_service()
	{
		struct Service {
			get_running_big_app_fn running_big_app = nullptr;
			get_app_title_id_fn app_title_id = nullptr;
		};

		static Service service = [] {
			Service resolved;

			void* handle = dlopen("libSceSystemService.sprx", RTLD_LAZY);
			if (!handle)
				return resolved;

			resolved.running_big_app = (get_running_big_app_fn)dlsym(handle, "sceSystemServiceGetAppIdOfRunningBigApp");
			resolved.app_title_id = (get_app_title_id_fn)dlsym(handle, "sceSystemServiceGetAppTitleId");

			logf("system service: running_app=%p title_id=%p",
				(void*)resolved.running_big_app,
				(void*)resolved.app_title_id);
			return resolved;
			}();

		return service;
	}

	void detect_targets(std::unordered_set<pid_t>& seen)
	{
		auto& service = resolve_system_service();

		if (service.running_big_app && service.app_title_id) {
			int app_id = service.running_big_app();
			if (app_id >= 0) {
				char title[32] = {};
				if (service.app_title_id(app_id, title) == 0 && title[0]) {
					pid_t pid = find_app_pid(app_id);
					if (pid > 1 && !find_target(pid) && !seen.count(pid)) {
						if (!collect_plugins(title).empty())
							add_target(pid, title);
						else
							seen_insert(seen, pid);
					}
					return;
				}
			}
		}

		for (pid_t pid : collect_process_ids()) {
			if (seen.count(pid) || find_target(pid))
				continue;

			std::string title;
			if (read_app_title_id(pid, title) != 0)
				continue;

			if (collect_plugins(title).empty()) {
				seen_insert(seen, pid);
				continue;
			}

			add_target(pid, title);
		}
	}

	struct TargetStats {
		int pending;
		int loaded;
		int failed;
	};

	TargetStats target_stats(const Target& target)
	{
		TargetStats stats = { -1, 0, 0 };

		for (size_t i = 0; i < target.state.size(); i++) {
			if (target.state[i] == kStatePending) {
				if (stats.pending < 0)
					stats.pending = (int)i;
			}
			else if (target.state[i] == kLoaded)
				stats.loaded++;
			else
				stats.failed++;
		}

		return stats;
	}

	void heartbeat()
	{
		long now = now_ms();
		if (now < g_next_heartbeat_ms)
			return;

		g_next_heartbeat_ms = now + 1000;

		for (const Target& target : g_targets) {
			std::vector<ResolvedPlugin> plugins = collect_plugins(target.title);
			int pending = target_stats(target).pending;
			std::string next = "none";

			if (pending >= 0 && pending < (int)plugins.size()) {
				next = format("%s (%+ld ms, %s)",
					file_name(plugins[pending].path.c_str()),
					target.next_at_ms - now,
					dependencies_text(target.pid,
						plugins[pending].path).c_str());
			}

			logf("heartbeat: [%s] pid %d up +%ld ms, ready=%d, main=%#lx, "
				"next=%s", target.title.c_str(), target.pid,
				now - target.detected_ms, target.ready_ms >= 0,
				(unsigned long)kernel_dynlib_mapbase_addr(target.pid, 0),
				next.c_str());
		}
	}

	void service_targets(std::unordered_set<pid_t>& seen)
	{
		for (size_t index = 0; index < g_targets.size();) {
			Target& target = g_targets[index];

			auto drop = [&]() {
				seen_insert(seen, target.pid);
				g_targets.erase(g_targets.begin() + index);
			};

			std::vector<ResolvedPlugin> plugins = collect_plugins(target.title);

			if (plugins.empty()) {
				drop();
				continue;
			}

			if (target.state.size() != plugins.size())
				target.state.resize(plugins.size(), kStatePending);

			TargetStats stats = target_stats(target);

			if (stats.pending < 0) {
				notify("[%s] done: %d of %d failed", target.title.c_str(),
					stats.failed, (int)plugins.size());
				logf("[%s] all plugins handled (%d failed)", target.title.c_str(),
					stats.failed);
				drop();
				continue;
			}

			if (target.ready_ms < 0) {
				long now = now_ms();
				int observed = target_observe(target.pid);

				if (observed != target.observed) {
					target.observed = observed;
					logf("[%s] image now %s", target.title.c_str(),
						target_observe_text(observed).c_str());
				}

				if (target_is_ready(target.pid)) {
					target.ready_ms = now;
					int first = target_stats(target).pending;
					target.next_at_ms = now + (first >= 0 ? plugins[first].delay_ms : 0);
					logf("[%s] image ready +%ld ms after detection (absolute %ld ms): "
						"the delay clock starts now (first plugin in %d ms)",
						target.title.c_str(), now - target.detected_ms, now,
						first >= 0 ? plugins[first].delay_ms : 0);
				}
				else if (now - target.detected_ms >= kImageWaitMs) {
					logf("[%s] no image evidence after %ld ms; dropping the pid",
						target.title.c_str(), kImageWaitMs);
					drop();
					continue;
				}
				else {
					index++;
					continue;
				}
			}

			if (g_options.expose_data && !target.data_mounted &&
				target.bind_passes < kBindPasses &&
				now_ms() >= target.mount_retry_at_ms) {
				std::vector<std::string> mounts;
				if (mount_system_data(target.pid, target.title, mounts)) {
					target.data_mounted = true;
					target.data_mounts = mounts;
				}
				else if (!target.mount_fail_notified &&
					target.bind_passes + 1 == kBindPasses) {
					target.mount_fail_notified = true;
					logf("[%s] /data mirror unavailable; main-thread plugins "
						"use the transient sandbox escape instead",
						target.title.c_str());
				}

				target.bind_passes++;
				target.mount_retry_at_ms = now_ms() + kBindRetryMs;
			}

			long now = now_ms();
			if (now < target.next_at_ms) {
				index++;
				continue;
			}

			int pending = target_stats(target).pending;
			if (pending < 0) {
				index++;
				continue;
			}

			ResolvedPlugin plugin = plugins[pending];
			Credentials saved;

			auto plugin_notify = [&](const char* outcome) {
				notify("[%s] %s - %s", target.title.c_str(),
					file_name(plugin.path.c_str()), outcome);
			};

			auto fail = [&](const std::string& reason, bool restore) {
				if (restore)
					restore_credentials(target.pid, saved);
				logf("[%s] %s: %s", target.title.c_str(), plugin.path.c_str(), reason.c_str());
				plugin_notify("Failed");
				target.state[pending] = kFailed;
				target.dep_missing.clear();
				target.dep_gave_up = false;
				target.next_at_ms = now_ms() + kSlowRetryMs;
				index++;
			};

			if (!process_is_alive(target.pid)) {
				logf("[%s] target died before plugin %s", target.title.c_str(),
					plugin.path.c_str());
				release_target_data_mount(target);
				drop();
				continue;
			}

			if (access(plugin.path.c_str(), R_OK) != 0) {
				fail(format("not found (errno %d)", errno), false);
				continue;
			}

			int load_up = remote_resolve_nid(target.pid, kNidLoadStartModule) != 0;
			int pthread_up = remote_resolve_nid(target.pid, kNidPthreadCreate) != 0;

			if (load_up != target.load_up || pthread_up != target.pthread_up) {
				target.load_up = load_up;
				target.pthread_up = pthread_up;
				logf("[%s] loader state: load=%d pthread=%d (the title's own "
					"module loader is %s)", target.title.c_str(), load_up,
					pthread_up, (load_up && pthread_up) ? "up" : "not up yet");
			}

			if (!load_up || !pthread_up) {
				target.next_at_ms = now + kRetryMs;
				index++;
				continue;
			}

			std::vector<std::string> missing;
			int missing_count = missing_dependencies(target.pid, plugin.path, missing);

			if (missing_count > 0) {
				if (target.dep_missing.empty()) {
					target.dep_since_ms = now;
					target.dep_gave_up = false;
				}
				if (target.dep_missing != missing) {
					target.dep_missing = missing;
					logf("[%s] %s: waiting for %d of %d libraries the plugin "
						"declares: %s", target.title.c_str(), plugin.path.c_str(),
						missing_count, (int)plugin_deps(plugin.path).declared.size(),
						join_names(missing).c_str());
				}

				if (!target.dep_gave_up &&
					now - target.dep_since_ms < kDepWaitMs) {
					target.next_at_ms = now + kRetryMs;
					index++;
					continue;
				}

				if (!target.dep_gave_up) {
					logf("[%s] %s: still missing %s after %ld ms; injecting "
						"anyway (the title may trap on the first import call)",
						target.title.c_str(), plugin.path.c_str(),
						join_names(missing).c_str(), kDepWaitMs);
					target.dep_gave_up = true;
				}
			}
			else if (!target.dep_missing.empty()) {
				logf("[%s] %s: all declared libraries are loaded",
					target.title.c_str(), plugin.path.c_str());
				target.dep_missing.clear();
			}

			if (!capture_credentials(target.pid, saved)) {
				fail("cannot read credentials", false);
				continue;
			}

			if (!grant_ucred(target.pid)) {
				fail("cannot grant privileges", true);
				continue;
			}

			bool sandbox_escaped = false;
			int access_code = 0;
			bool native_sandbox = target.data_mounted &&
				remote_access(target.pid, plugin.path, access_code) == 0;

			if (!native_sandbox) {
				logf("[%s] %s: %s; pointing rootdir/jaildir at the kernel "
					"root for this load", target.title.c_str(),
					plugin.path.c_str(),
					target.data_mounted ?
						"not readable from the title's sandbox" :
						"/data is not mirrored in the sandbox");
				sandbox_escaped = grant_sandbox(target.pid);
				if (!sandbox_escaped) {
					fail("cannot open the sandbox", true);
					continue;
				}
			}

			logf("[%s] injecting %s (attempt %d, sandbox %s, %s); main=%#lx",
				target.title.c_str(), plugin.path.c_str(),
				target.refusals + 1,
				sandbox_escaped ? "escaped" : "native",
				dependencies_text(target.pid, plugin.path).c_str(),
				(unsigned long)kernel_dynlib_mapbase_addr(target.pid, 0));

			LoadResult result = load_plugin(target.pid, plugin.path,
				plugin.main_thread);

			bool loaded = result == LoadResult::Confirmed ||
				result == LoadResult::Started;

			if (!restore_credentials(target.pid, saved))
				notify("[%s] cannot restore credentials", target.title.c_str());

			if (result == LoadResult::Again) {
				target.refusals++;
				if (target.refusals >= kMaxRefusals) {
					logf("[%s] %s: the title refused %d times, giving up",
						target.title.c_str(), plugin.path.c_str(), target.refusals);
					plugin_notify("Failed");
					target.state[pending] = kFailed;
					target.dep_missing.clear();
					target.dep_gave_up = false;
					target.next_at_ms = now + kSlowRetryMs;
				}
				else {
					long retry_ms = plugin.main_thread ? kMainRetryMs : kRetryMs;
					logf("[%s] %s: not ready yet (refusal %d of %d), retrying "
						"in %ld ms", target.title.c_str(), plugin.path.c_str(),
						target.refusals, kMaxRefusals, retry_ms);
					target.next_at_ms = now_ms() + retry_ms;
				}
				index++;
				continue;
			}

			target.refusals = 0;

			if (loaded) {
				target.state[pending] = kLoaded;
				logf("[%s] %s -> %s", target.title.c_str(),
					plugin.path.c_str(),
					result == LoadResult::Confirmed ? "Success" : "Starting");
				plugin_notify(result == LoadResult::Confirmed ?
					"Success" : "Starting");
			}
			else {
				target.state[pending] = kFailed;
				logf("[%s] %s -> Failed", target.title.c_str(), plugin.path.c_str());
				plugin_notify("Failed");
			}

			target.dep_missing.clear();
			target.dep_gave_up = false;

			int next = pending + 1 < (int)plugins.size() ? pending + 1 : pending;
			target.next_at_ms = now_ms() + plugins[next].delay_ms;

			if (loaded && g_options.expose_data && !target.data_repaired) {
				repair_target_data(target.pid);
				target.data_repaired = true;
			}

			index++;
		}
	}

	pid_t read_lock_owner(const char* path)
	{
		FILE* file = fopen(path, "r");
		if (!file)
			return 0;

		char text[32] = {};
		pid_t owner = 0;
		if (fgets(text, sizeof(text), file))
			owner = (pid_t)atoi(text);
		fclose(file);

		return owner;
	}

	bool acquire_lock()
	{
		for (;;) {
			int fd = open(kLockPath, O_WRONLY | O_CREAT | O_EXCL, 0644);
			if (fd >= 0) {
				char text[32];
				int length = snprintf(text, sizeof(text), "%d\n", getpid());
				ssize_t written = write(fd, text, (size_t)length);
				close(fd);
				if (written == length)
					return true;
				unlink(kLockPath);
				return false;
			}

			if (errno != EEXIST)
				return false;

			pid_t owner = read_lock_owner(kLockPath);
			if (owner <= 1) {
				usleep(10000);
				owner = read_lock_owner(kLockPath);
			}

			if (owner > 1 && process_is_alive(owner))
				return false;

			char stale[64];
			snprintf(stale, sizeof(stale), "%s.%d", kLockPath, (int)getpid());

			if (rename(kLockPath, stale) != 0) {
				if (errno == ENOENT)
					continue;
				return false;
			}

			pid_t taken = read_lock_owner(stale);
			for (int i = 0; i < 10 && taken <= 1; i++) {
				usleep(10000);
				taken = read_lock_owner(stale);
			}

			if (taken > 1 && process_is_alive(taken)) {
				link(stale, kLockPath);
				unlink(stale);
				return false;
			}

			unlink(stale);
		}
	}

	void release_lock()
	{
		char mine[32];
		snprintf(mine, sizeof(mine), "%d", getpid());

		FILE* file = fopen(kLockPath, "r");
		if (!file)
			return;

		char text[32] = {};
		bool owns = fgets(text, sizeof(text), file) &&
			trim(text) == mine;
		fclose(file);

		if (owns)
			unlink(kLockPath);
	}

	void run()
	{
		std::unordered_set<pid_t> seen;

		long started = now_ms();
		long timeout_ms = (long)g_options.timeout_s * 1000L;

		while (now_ms() - started < timeout_ms) {
			for (auto it = seen.begin(); it != seen.end();) {
				if (process_is_alive(*it))
					++it;
				else
					it = seen.erase(it);
			}
			drop_dead_targets();
			detect_targets(seen);
			service_targets(seen);
			heartbeat();
			usleep(kScanIntervalMs * 1000);
		}

		logf("timeout after %d s", g_options.timeout_s);
	}

}

int main()
{
	g_log_start_ms = now_ms();

	signal(SIGSEGV, SIG_DFL);
	signal(SIGBUS, SIG_DFL);

	if (!acquire_lock()) {
		printf("another ploader is running, or the lock is held: %s\n", kLockPath);
		return 0;
	}

	Options defaults;
	g_options = defaults;

	bool config_ok = config_load(kConfigPath);
	log_open(kLogPath);

	logf("================================================================");
	logf("pid %d, uid %d, monotonic base %ld ms", (int)getpid(), (int)getuid(), now_ms());
	logf("own authid %#llx", (unsigned long long)kernel_get_ucred_authid(getpid()));

	if (!config_ok) {
		logf("config not found: %s", kConfigPath);
		notify("config not found");
		console_out("config not found at %s", kConfigPath);
		release_lock();
		return 0;
	}

	if (!g_warning.empty()) {
		logf("config warning: %s", g_warning.c_str());
		notify("config: %s", g_warning.c_str());
	}

	logf("options: timeout_s=%d delay_ms=%d debug_log=%d console_log=%d "
		"expose_data=%d", g_options.timeout_s,
		g_options.delay_ms, g_options.debug_log, g_options.console_log,
		g_options.expose_data);

	if (!has_enabled_plugins()) {
		logf("no enabled plugins configured");
		notify("no valid plugins configured");
		console_out("no valid plugins configured in %s", kConfigPath);
		release_lock();
		return 0;
	}

	for (const PluginConfig& plugin : g_plugins) {
		logf("plugin: title=%s path=%s inject=%d delay_ms=%d main_thread=%d", plugin.title.c_str(), plugin.path.c_str(), plugin.inject, plugin.delay_ms, plugin.main_thread);
		log_plugin_deps(plugin.path);
	}

	notify("Started!");
	resolve_system_service();

	console_out("pid %d, %d plugin(s) configured, watching %d s", (int)getpid(), (int)g_plugins.size(), g_options.timeout_s);
	logf("watching for %d s", g_options.timeout_s);
	run();

	console_out("done after %d s, exiting", g_options.timeout_s);
	logf("exiting");
	notify("Exiting...");

	if (g_log)
		fclose(g_log);

	release_lock();
	return 0;
}
