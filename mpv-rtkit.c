// SPDX-License-Identifier: EUPL-1.2-or-later

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/resource.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <sched.h>

#include <linux/sched.h>
#include <sys/syscall.h>

#include <mpv/client.h>
#include <dbus/dbus.h>

#ifndef TASK_COMM_LEN
#	define TASK_COMM_LEN 16
#endif

#ifdef __has_builtin
#	if __has_builtin(__builtin_expect)
#		define expect(expr, pred) __builtin_expect(expr, pred)
#	endif

/*
#	if __has_builtin(__builtin_fprintf_unlocked)
#		define fprintf_unlocked(stream, format, ...) __builtin_fprintf_unlocked(stream, format __VA_OPT__(,) __VA_ARGS__)
#	endif
*/

#	if __has_builtin(__builtin_vfprintf_unlocked)
#		define vfprintf_unlocked(stream, format, ap) __builtin_vfprintf_unlocked(stream, format, ap)
#	endif

#	if __has_builtin(__builtin_fputs_unlocked)
#		define fputs_unlocked(string, stream) __builtin_fputs_unlocked(string, stream)
#	endif
#endif

#ifndef expect
#	define expect(expr, pred) (expr)
#endif

#ifndef fprintf_unlocked
#	define fprintf_unlocked(stream, format, ...) fprintf(stream, format __VA_OPT__(,) __VA_ARGS__)
#endif

#ifndef vfprintf_unlocked
#	define vfprintf_unlocked(stream, format, ap) vfprintf(stream, format, ap)
#endif

#ifndef fputs_unlocked
#	define fputs_unlocked(string, stream) fputs(string, stream)
#endif

#define likely(expr) expect(!!(expr), 1)
#define unlikely(expr) expect(!!(expr), 0)

enum LogLevel {
	LOG_CRIT,
	LOG_ERR,
	LOG_WARN,
	LOG_INFO,
	LOG_DEBUG
};

struct Context {
	char path[[gnu::aligned]][PATH_MAX];
	char buf[[gnu::aligned]][256];
	struct mpv_handle *mpv;
	FILE *err;
	DBusConnection *dbus;
	int proc;
	bool tty;
};

static char const task_path[] = "/proc/self/task";

// Needed for sched_(get|set)scheduler on musl
extern long syscall(long, ...);

// Weak symbols for libmpv functions to avoid linking errors
[[gnu::weak, nodiscard, gnu::const]]
unsigned long int mpv_client_api_version();

[[gnu::weak, nodiscard, gnu::pure, gnu::returns_nonnull, gnu::nonnull(1)]]
char const *mpv_client_name(struct mpv_handle *restrict);

[[gnu::weak, nodiscard, gnu::returns_nonnull, gnu::nonnull(1)]]
struct mpv_event *mpv_wait_event(struct mpv_handle *restrict, double);

[[nodiscard, gnu::const]]
static uint_least8_t mesg_attr(enum LogLevel level) {
	switch (level) {
	case LOG_CRIT:
		return 1;
	case LOG_DEBUG:
		return 2;
	default:
		return 0;
	}
}

[[nodiscard, gnu::const]]
static uint_least8_t mesg_colour(enum LogLevel level) {
	switch (level) {
	case LOG_CRIT:
	case LOG_ERR:
		return 31;
	case LOG_WARN:
		return 33;
	default:
		return 37;
	}
}

[[gnu::nonnull(1, 3), gnu::format(printf, 3, 4), gnu::access(read_only, 3)]]
static void mesg(struct Context *restrict context, enum LogLevel level, char const *restrict format, ...) {
	int errn = errno;
	
	if (context->tty) {
		fprintf_unlocked(context->err, "\e[%" PRIuLEAST8 ";%" PRIuLEAST8 "m", mesg_attr(level), mesg_colour(level));
	}

	fprintf_unlocked(context->err, "%s: ", mpv_client_name(context->mpv));

	va_list ap;
	va_start(ap, format);
	errno = errn;
	vfprintf_unlocked(context->err, format, ap);
	va_end(ap);

	if (context->tty) {
		fputs_unlocked("\e[0;39m", context->err);
	}

	putc_unlocked('\n', context->err);
}

[[nodiscard, gnu::nonnull(1, 2, 3),
	gnu::null_terminated_string_arg(2),	gnu::null_terminated_string_arg(3),
	gnu::access(read_only, 2), gnu::access(read_only, 3)]]
static DBusMessage *rtkit_call(struct Context *restrict context,
	char const *restrict iface, char const *restrict method, int first, ...) {
	DBusMessage *call = dbus_message_new_method_call("org.freedesktop.RealtimeKit1", "/org/freedesktop/RealtimeKit1", iface, method);
	if (unlikely(!call)) {
		mesg(context, LOG_ERR, "Unable to allocate memory for D‐Bus message");
		goto failure;
	}

	va_list ap;
	va_start(ap, first);
	if (unlikely(!dbus_message_append_args_valist(call, first, ap))) {
		mesg(context, LOG_ERR, "Unable to allocate memory for D‐Bus message");
		goto unref_call;
	}
	va_end(ap);

	DBusError error = DBUS_ERROR_INIT;
	DBusMessage *resp = dbus_connection_send_with_reply_and_block(context->dbus, call, 100, &error);
	if (unlikely(!resp)) {
		mesg(context, LOG_ERR, "Failed to send D‐Bus message: %s", error.message);
		goto free_error;
	}

	if (unlikely(dbus_set_error_from_message(&error, resp))) {
		mesg(context, LOG_ERR, "%s.%s: %s", iface, method, error.message);
		goto unref_resp;
	}

	return resp;

unref_resp:
	dbus_message_unref(resp);

free_error:
	dbus_error_free(&error);

unref_call:
	dbus_message_unref(call);

failure:
	return nullptr;
};

[[nodiscard, gnu::nonnull(1, 2), gnu::null_terminated_string_arg(2), gnu::access(read_only, 2)]]
static int_least64_t rtkit_property(struct Context *restrict context, char const *property) {
	char const *iface = "org.freedesktop.RealtimeKit1";
	int_least64_t value = -1;

	DBusMessage *resp = rtkit_call(context, "org.freedesktop.DBus.Properties", "Get",
		DBUS_TYPE_STRING, &iface,
		DBUS_TYPE_STRING, &property,
		DBUS_TYPE_INVALID);
	if (unlikely(!resp)) {
		mesg(context, LOG_ERR, "Failed to request %s property from RealtiemKit", property);
		goto exit;
	}

	DBusMessageIter iter;
	dbus_message_iter_init(resp, &iter);

	if (unlikely(dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)) {
		mesg(context, LOG_ERR, "Malformed D‐Bus message: Expected variant type");
		goto unref_resp;
	}

	DBusMessageIter sub;
	dbus_message_iter_recurse(&iter, &sub);

	switch (dbus_message_iter_get_arg_type(&sub)) {
	case DBUS_TYPE_INT32:
		int32_t i32;
		dbus_message_iter_get_basic(&sub, &i32);
		value = i32;
		break;

	case DBUS_TYPE_INT64:
		int64_t i64;
		dbus_message_iter_get_basic(&sub, &i64);
		value = i64;
		break;

	default:
		mesg(context, LOG_ERR, "Malformed D‐Bus message: Expected integer type");
		goto unref_resp;
	}

unref_resp:
	dbus_message_unref(resp);

exit:
	return value;
}

[[nodiscard, gnu::nonnull(1)]]
static int_least64_t rtkit_realtime_max(struct Context *restrict context) {
	return rtkit_property(context, "MaxRealtimePriority");
}

[[nodiscard, gnu::nonnull(1)]]
static int_least64_t rtkit_rttime_max(struct Context *restrict context) {
	return rtkit_property(context, "RTTimeUSecMax");
}

[[nodiscard, gnu::nonnull(1)]]
static bool rtkit_make_realtime(struct Context *restrict context, pid_t thread, uint_least32_t priority) {
	uint64_t rtk_thread = thread;
	uint32_t rtk_priority = priority;

	DBusMessage *resp = rtkit_call(context, "org.freedesktop.RealtimeKit1", "MakeThreadRealtime",
		DBUS_TYPE_UINT64, &rtk_thread,
		DBUS_TYPE_UINT32, &rtk_priority,
		DBUS_TYPE_INVALID);
	if (unlikely(!resp)) {
		mesg(context, LOG_ERR, "Failed to elevate thread %i to real‐time priority %" PRIuLEAST32, thread, priority);
		goto failure;
	}

	dbus_message_unref(resp);
	return true;

failure:
	return false;
}

[[nodiscard,
	gnu::nonnull(1, 2, 3), gnu::null_terminated_string_arg(3),
	gnu::access(read_only, 2), gnu::access(write_only, 3, 4)]]
static ssize_t cat(struct Context *restrict context, char const *restrict path, char *restrict buf, size_t len) {
	int fd = openat(context->proc, path, O_RDONLY | O_CLOEXEC);
	if (unlikely(fd < 0)) {
		mesg(context, LOG_ERR, "openat(%s, %s, O_RDONLY | O_CLOEXEC): %m", task_path, context->path);
		goto failure;
	}

	ssize_t rlen = read(fd, buf, len);
	if (unlikely(rlen < 0)) {
		mesg(context, LOG_ERR, "read(%s/%s, %p, %zu): %m", task_path, context->path, buf, len);
		goto close;
	}

	if (unlikely(buf[rlen - 1] != '\n')) {
		if ((size_t) rlen == len) {
			mesg(context, LOG_ERR, "Insufficient buffer size: %zu", len);
		} else {
			mesg(context, LOG_ERR, "No terminating new line within %zi bytes read from file", rlen);
		}
		goto failure;
	}

	return rlen - 1;

close:
	close(fd);

failure:
	return -1;
}

[[nodiscard, gnu::pure,
	gnu::nonnull(1, 2), gnu::null_terminated_string_arg(2),
	gnu::access(read_only, 1, 3), gnu::access(read_only, 2, 3)]]
static bool cmp(char const *restrict mem, char const *restrict str, size_t len) {
	return len == strlen(str) && !memcmp(mem, str, len);
}

[[nodiscard, gnu::pure,
	gnu::nonnull(1, 2), gnu::null_terminated_string_arg(2),
	gnu::access(read_only, 1, 3), gnu::access(read_only, 2, 3)]]
static bool pre(char const *restrict mem, char const *restrict str, size_t len) {
	return len >= strlen(str) && !memcmp(mem, str, strlen(str));
}

// Saturating subtraction
[[nodiscard, gnu::const]]
static uint32_t sub(uint32_t min, uint32_t sub) {
#if __has_builtin(__builtin_sub_overflow)
	uint32_t diff;
	return __builtin_sub_overflow(min, sub, &diff) ? 0 : diff;
#else
	int64_t diff = (int64_t) min - (int64_t sub);
	return diff >= 0 ? (uint32_t) diff : 0;
#endif
}

[[nodiscard, gnu::const, gnu::returns_nonnull]]
static char const *sched_name(int policy) {
	switch (policy & ~SCHED_RESET_ON_FORK) {
	case SCHED_NORMAL:
		return "normal";
	case SCHED_FIFO:
		return "fifo";
	case SCHED_RR:
		return "round‐robin";
	case SCHED_BATCH:
		return "batch";
	case SCHED_IDLE:
		return "idle";
	case SCHED_DEADLINE:
		return "deadline";
	default:
		return "unknown";
	}
}

[[gnu::nonnull(1)]]
static bool elevate_threads(struct Context *restrict context, uint_least32_t max) {
	bool status = false;
	DIR *dir;

	{
		int fd = fcntl(context->proc, F_DUPFD_CLOEXEC);
		if (unlikely(fd < 0)) {
			mesg(context, LOG_ERR, "fcntl(%i, F_DUPFD_CLOEXEC): %m", fd);
			goto exit;
		}

		dir = fdopendir(fd);
		if (unlikely(!dir)) {
			mesg(context, LOG_ERR, "fdopendir(%i): %m", fd);
			close(fd);
			goto exit;
		}
	}

	errno = 0;
	struct dirent *ent;
	while ((ent = readdir(dir))) {
		// Skip non‐numeric entries
		for (size_t iter = 0; ent->d_name[iter] != '\0'; ++iter) {
			if (!isdigit(ent->d_name[iter])) {
				goto loop;
			}
		}

		pid_t thread = atoi(ent->d_name);
		assert(thread >= 0);

		{
			int len = snprintf(context->path, sizeof context->path, "%s/comm", ent->d_name);
			if (unlikely(len < 0)) {
				mesg(context, LOG_ERR, "snprintf: %m");
				goto closedir;
			}

			// Assert that path name fits into buffer
			assert((size_t) len < sizeof context->path);
		}

		// Command name buffer
		char comm[[gnu::aligned, gnu::nonstring]][TASK_COMM_LEN + 1];

		ssize_t rlen = cat(context, context->path, comm, sizeof comm);
		if (unlikely(rlen < 0)) {
			mesg(context, LOG_ERR, "Failed to read %s/%s", task_path, context->path);
			goto loop;
		}

		int policy = syscall(SYS_sched_getscheduler, thread);
		if (unlikely(policy < 0)) {
			mesg(context, LOG_ERR, "Unable to determine scheduling policy for %.*s (%i): %m", (int) rlen, comm, thread);
			goto loop;
		}

		if ((policy & ~SCHED_RESET_ON_FORK) != SCHED_NORMAL) {
			mesg(context, LOG_DEBUG, "Skipping task %.*s (%i) with %s scheduling policy", (int) rlen, comm, thread, sched_name(policy));
			goto loop;
		}

		uint_least32_t prio;

		if (cmp(comm, "mpv/ao/pipewire", rlen) || pre(comm, "data-loop.", rlen)) {
			prio = max;
		} else if (cmp(comm, "vo", rlen)) {
			prio = sub(max, 1);
		} else {
			mesg(context, LOG_DEBUG, "Skipping unknown task %.*s (%i)", (int) rlen, comm, thread);
			goto loop;
		}

		if (!(policy & SCHED_RESET_ON_FORK)) {
			mesg(context, LOG_DEBUG, "Setting reset‐on‐fork flag on task %.*s (%i)", (int) rlen, comm, thread);

			struct sched_param param;
			
			if (unlikely(syscall(SYS_sched_getparam, thread, &param))) {
				mesg(context, LOG_ERR, "Unable to determine scheduling parameters for task %.*s (%i): %m", (int) rlen, comm, thread);
				goto loop;
			}

			if (unlikely(syscall(SYS_sched_setscheduler, thread, policy | SCHED_RESET_ON_FORK, &param))) {
				mesg(context, LOG_ERR, "Failed to set reset‐on‐fork flag on task %.*s (%i): %m", (int) rlen, comm, thread);
				goto loop;
			}
		}

		mesg(context, LOG_INFO, "Elevating task %.*s (%i) to real‐time priority %" PRIu32, (int) rlen, comm, thread, prio);

		if (unlikely(!rtkit_make_realtime(context, thread, prio))) {
			mesg(context, LOG_ERR, "Failed to elevate task %.*s (%i) to real‐time priority %" PRIu32, (int) rlen, comm, thread, prio);
			goto loop;
		}

loop:
		// Reset errno to distinguish end‐of‐directory condition from errors
		errno = 0;
	}

	if (unlikely(errno)) {
		mesg(context, LOG_ERR, "readdir(%s): %m", task_path);
		goto closedir;
	}

	status = true;

closedir:
	closedir(dir);
	
exit:
	return status;
}

[[nodiscard, gnu::nonnull(1, 2)]]
static bool context_init(struct Context *restrict context, struct mpv_handle *restrict mpv) {
	context->mpv = mpv;
	context->tty = isatty(2);

	// Fall back to stderr during initialisation
	context->err = stderr;

	{
		int fd = dup(2);
		if (unlikely(fd < 0)) {
			mesg(context, LOG_CRIT, "dup(2): %m");
			goto failure;
		}

		FILE *err = fdopen(fd, "w");
		if (unlikely(!err)) {
		  mesg(context, LOG_CRIT, "fdopen(%i, w): %m", fd);
			close(fd);
		  goto failure;
		}

		context->err = err;
	}

	if (unlikely(setvbuf(context->err, context->buf, _IOLBF, sizeof context->buf))) {
		mesg(context, LOG_CRIT, "setvbuf: %m");
		goto fclose;
	}

	context->proc = open(task_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (unlikely(context->proc < 0)) {
		mesg(context, LOG_CRIT, "open(%s, O_RDONLY | O_DIRECTORY | O_CLOEXEC): %m", task_path);
		goto fclose;
	}

	DBusError error = DBUS_ERROR_INIT;
	context->dbus = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	if (unlikely(!context->dbus)) {
		mesg(context, LOG_CRIT, "Failed to open connection to D‐Bus system bus: %s", error.message);
		goto close;
	}

	return true;

close:
	close(context->proc);

fclose:
	fclose(context->err);

failure:
	/* memset(context, 0, sizeof *context); */
	return false;
}

[[gnu::nonnull(1)]]
static void context_destroy(struct Context *restrict context) {
	close(context->proc);
	dbus_connection_unref(context->dbus);
	fclose(context->err);
	/* memset(context, 0, sizeof *context); */
}

[[nodiscard, gnu::const]]
uint_least16_t major(uint_least32_t version) {
	return (uint_least16_t) (version >> 16);
}

[[nodiscard, gnu::const]]
uint_least16_t minor(uint_least32_t version) {
	return (uint_least16_t) (version & ((1 << 16) - 1));
}

[[gnu::visibility("default"), gnu::nonnull(1)]]
int mpv_open_cplugin(struct mpv_handle *restrict mpv) {
	struct Context context;

	if (unlikely(!context_init(&context, mpv))) {
		goto failure;
	}

	if (major(MPV_CLIENT_API_VERSION) != major(mpv_client_api_version())) {
		mesg(&context, LOG_CRIT, "Incompatible mpv client API versions: "
			"Built with version %" PRIuLEAST16 ".%" PRIuLEAST16 ", "
			"but run with version %" PRIuLEAST16 ".%" PRIuLEAST16,
			major(MPV_CLIENT_API_VERSION), minor(MPV_CLIENT_API_VERSION),
			major(mpv_client_api_version()), minor(mpv_client_api_version()));
		goto destroy;
	} else if (minor(MPV_CLIENT_API_VERSION) > minor(mpv_client_api_version())) {
		mesg(&context, LOG_WARN, "Potentially incompatible mpv client API versions: "
			"Built with version %" PRIuLEAST16 ".%" PRIuLEAST16 ", "
			"but run with version %" PRIuLEAST16 ".%" PRIuLEAST16,
			major(MPV_CLIENT_API_VERSION), minor(MPV_CLIENT_API_VERSION),
			major(mpv_client_api_version()), minor(mpv_client_api_version()));
	} else {
		mesg(&context, LOG_DEBUG, "mpv client API version %" PRIuLEAST16 ".%" PRIuLEAST16 " "
		  "(built with %" PRIuLEAST16 ".%" PRIuLEAST16 ")",
			major(MPV_CLIENT_API_VERSION), minor(MPV_CLIENT_API_VERSION),
			major(mpv_client_api_version()), minor(mpv_client_api_version()));
	}

	{
		int_least64_t rttime_max = rtkit_rttime_max(&context);
		if (unlikely(rttime_max < 0)) {
		  mesg(&context, LOG_CRIT, "Failed to determine maximum real‐time period");
		  goto destroy;
		}

		mesg(&context, LOG_INFO, "Limiting maximum real‐time period to %" PRIiLEAST64 " µs", rttime_max);

		struct rlimit rlim = {
		  .rlim_cur = rttime_max,
		  .rlim_max = rttime_max
		};

		if (unlikely(setrlimit(RLIMIT_RTTIME, &rlim))) {
		  mesg(&context, LOG_CRIT, "setrlimit(RLIMIT_RTTIME, { %" PRIiLEAST64 ", %" PRIiLEAST64 " }): %m", rttime_max, rttime_max);
		  goto destroy;
		}
	}

	int_least32_t prio_max = rtkit_realtime_max(&context);
	if (unlikely(prio_max < 0)) {
		mesg(&context, LOG_CRIT, "Failed to determine maximum real‐time priority");
		goto destroy;
	}

	mesg(&context, LOG_INFO, "Maximum real‐time priority %" PRIiLEAST32, prio_max);

	while (true) {
		struct mpv_event *event = mpv_wait_event(mpv, 0.0);
		assert(event);

		switch (event->event_id) {
		case MPV_EVENT_FILE_LOADED:
		case MPV_EVENT_VIDEO_RECONFIG:
		case MPV_EVENT_AUDIO_RECONFIG:
			if (unlikely(!elevate_threads(&context, prio_max))) {
				mesg(&context, LOG_WARN, "Failed to elevate some threads");
			}
			break;

		case MPV_EVENT_SHUTDOWN:
		  goto success;

		default:
		  continue;
		}
	}

success:
	return 0;

destroy:
	context_destroy(&context);

failure:
	return -1;
}
