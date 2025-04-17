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


#ifndef TASK_COMM_LEN
#	define TASK_COMM_LEN 16u
#endif


#define PRI_NICE PRIiFAST8
#define PRI_RTPRIO PRIuFAST8

#define NICE_C(n) INT8_C(n)
#define RTPRIO_C(n) UINT8_C(n)

typedef int_fast8_t Nice;
typedef uint_fast8_t RtPrio;

enum NiceLimits : Nice {
	NICE_MIN = PRIO_MIN,
	NICE_MAX = PRIO_MAX,
	NICE_INV = INT8_MAX,
};

enum RtPrioLimits : RtPrio {
	RTPRIO_INV = RTPRIO_C(0),
	RTPRIO_MIN = RTPRIO_C(1),
	RTPRIO_MAX = RTPRIO_C(99),
};


enum LogLevel : uint_fast8_t {
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
	Nice nice_min;
	RtPrio rtprio_max;
};


struct Thread {
	char comm[[gnu::aligned, gnu::nonstring]][TASK_COMM_LEN + 1u];
	pid_t pid;
	uint_fast8_t len;
};


static char const task_path[] = "/proc/self/task";


// needed for sched_(get|set)scheduler on musl
extern long syscall(long, ...);


// weak symbols for libmpv functions to avoid linking errors
[[gnu::weak, nodiscard, gnu::const]]
unsigned long int mpv_client_api_version();

[[gnu::weak, nodiscard, gnu::pure, gnu::returns_nonnull, gnu::nonnull(1)]]
char const *mpv_client_name(struct mpv_handle *restrict);

[[gnu::weak, nodiscard, gnu::returns_nonnull, gnu::nonnull(1)]]
struct mpv_event *mpv_wait_event(struct mpv_handle *restrict, double);


[[nodiscard, gnu::const]]
static inline bool rtprio_valid(RtPrio rtprio) {
	return rtprio >= RTPRIO_MIN && rtprio <= RTPRIO_MAX;
}

[[nodiscard, gnu::const]]
static inline bool nice_valid(Nice nice) {
	return nice >= NICE_MIN && nice <= NICE_MAX;
}

// saturating subtraction
[[nodiscard, gnu::const]]
static inline RtPrio rtprio_sub(RtPrio min, RtPrio sub) {
	assert(rtprio_valid(min) && rtprio_valid(sub));
	return min - sub >= RTPRIO_MIN ? min - sub : RTPRIO_MIN;
}

// saturating addition
[[nodiscard, gnu::const]]
static inline Nice nice_add(Nice add0, Nice add1) {
	assert(nice_valid(add0) && nice_valid(add1));
	return add0 + add1 <= NICE_MAX ? add0 + add1 : NICE_MAX;
}


[[nodiscard, gnu::const]]
static uint_fast8_t mesg_attr(enum LogLevel level) {
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
static uint_fast8_t mesg_colour(enum LogLevel level) {
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

[[gnu::nonnull(1, 3), gnu::format(printf, 3, 4), gnu::access(read_only, 1), gnu::access(read_only, 3)]]
static void mesg(struct Context const *restrict context, enum LogLevel level, char const *restrict format, ...) {
	int errn = errno;
	
	if (context->tty) {
		fprintf_unlocked(context->err, "\e[%" PRIuFAST8 ";%" PRIuFAST8 "m", mesg_attr(level), mesg_colour(level));
	}

	fprintf_unlocked(context->err, "%s: ", mpv_client_name(context->mpv));

	va_list ap;
	va_start(ap, format);
	errno = errn;
	vfprintf_unlocked(context->err, format, ap);
	va_end(ap);

	if (context->tty) {
		// reset graphics rendition
		fputs_unlocked("\e[0;39m", context->err);
	}

	putc_unlocked('\n', context->err);
}


[[nodiscard, gnu::nonnull(1, 2, 3),
	gnu::null_terminated_string_arg(2),	gnu::null_terminated_string_arg(3),
	gnu::access(read_only, 1), gnu::access(read_only, 2), gnu::access(read_only, 3)]]
static DBusMessage *rtkit_call(struct Context const *restrict context, char const *restrict iface,
                               char const *restrict method, int first, ...) {
	if (!context->dbus) {
		goto failure;
	}

	DBusMessage *call = dbus_message_new_method_call("org.freedesktop.RealtimeKit1", "/org/freedesktop/RealtimeKit1", iface, method);
	if (unlikely(!call)) {
		mesg(context, LOG_ERR, "Unable to allocate memory for D-Bus message");
		goto failure;
	}

	va_list ap;
	va_start(ap, first);
	if (unlikely(!dbus_message_append_args_valist(call, first, ap))) {
		mesg(context, LOG_ERR, "Unable to allocate memory for D-Bus message");
		goto unref_call;
	}
	va_end(ap);

	DBusError error = DBUS_ERROR_INIT;
	DBusMessage *resp = dbus_connection_send_with_reply_and_block(context->dbus, call, 100, &error);
	if (unlikely(!resp)) {
		mesg(context, LOG_ERR, "Failed to send D-Bus message and receive reply: %s", error.message);
		goto free_error;
	}

	if (unlikely(dbus_set_error_from_message(&error, resp))) {
		mesg(context, LOG_ERR, "RtKit: %s.%s: %s", iface, method, error.message);
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

[[nodiscard, gnu::nonnull(1, 2), gnu::null_terminated_string_arg(2), gnu::access(read_only, 1), gnu::access(read_only, 2)]]
static int_fast64_t rtkit_property(struct Context const *restrict context, char const *property, int_fast64_t invalid) {
	char const *iface = "org.freedesktop.RealtimeKit1";
	int_least64_t value = invalid;

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

[[nodiscard, gnu::nonnull(1), gnu::access(read_only, 1)]]
static RtPrio rtkit_realtime_max(struct Context const *restrict context) {
	return rtkit_property(context, "MaxRealtimePriority", RTPRIO_INV);
}

[[nodiscard, gnu::nonnull(1), gnu::access(read_only, 1)]]
static uint_fast64_t rtkit_rttime_max(struct Context const *restrict context) {
	return rtkit_property(context, "RTTimeUSecMax", 0u);
}

[[nodiscard, gnu::nonnull(1), gnu::access(read_only, 1)]]
static Nice rtkit_nice_min(struct Context const *restrict context) {
	return rtkit_property(context, "MinNiceLevel", NICE_INV);
}

[[gnu::nonnull(1), gnu::access(read_only, 1)]]
static bool rtkit_make_realtime(struct Context const *restrict context, pid_t thread, RtPrio rtprio) {
	uint64_t rtk_thread = thread;
	uint32_t rtk_rtprio = rtprio;

	DBusMessage *resp = rtkit_call(context, "org.freedesktop.RealtimeKit1", "MakeThreadRealtime",
		DBUS_TYPE_UINT64, &rtk_thread,
		DBUS_TYPE_UINT32, &rtk_rtprio,
		DBUS_TYPE_INVALID);
	if (unlikely(!resp)) {
		mesg(context, LOG_ERR, "Failed to elevate thread %i to real‐time priority %" PRI_RTPRIO " via RtKit", thread, rtprio);
		goto failure;
	}

	dbus_message_unref(resp);
	return true;

failure:
	return false;
}

[[gnu::nonnull(1), gnu::access(read_only, 1)]]
static bool rtkit_renice(struct Context const *restrict context, pid_t thread, Nice level) {
	uint64_t rtk_thread = thread;
	int32_t rtk_nice = level;

	DBusMessage *resp = rtkit_call(context, "org.freedesktop.RealtimeKit1", "MakeThreadHighPriority",
		DBUS_TYPE_UINT64, &rtk_thread,
		DBUS_TYPE_INT32, &rtk_nice,
		DBUS_TYPE_INVALID);
	if (unlikely(!resp)) {
		mesg(context, LOG_ERR, "Failed to set nice level of thread %i to %" PRI_NICE " via RtKit", thread, level);
		goto failure;
	}

	dbus_message_unref(resp);
	return true;

failure:
	return false;
}


[[gnu::nonnull(1, 2), gnu::access(read_write, 1), gnu::access(read_write, 2)]]
static bool thread_comm(struct Context *restrict context, struct Thread *restrict thread) {
	bool status = false;

	{
		int len = snprintf(context->path, sizeof context->path, "%i/comm", thread->pid);
		if (unlikely(len < 0)) {
			mesg(context, LOG_ERR, "snprintf(%p, %zu, \"%%i/comm\", %i): %m",
			     context->path, sizeof context->path, thread->pid);
			goto exit;
		}

		// assert that path name fits into buffer
		assert((size_t) len < sizeof context->path);
	}

	int fd = openat(context->proc, context->path, O_RDONLY | O_CLOEXEC);
	if (unlikely(fd < 0)) {
		mesg(context, LOG_ERR, "openat(%s [%i], %s, O_RDONLY|O_CLOEXEC): %m", task_path, fd, context->path);
		goto exit;
	}

	ssize_t rlen = read(fd, thread->comm, sizeof (thread->comm));
	if (unlikely(rlen < 0)) {
		mesg(context, LOG_ERR, "read(%s/%s [%i], %p, %zu): %m", task_path, context->path, fd, thread->comm, sizeof thread->comm);
		goto close;
	}

	if (unlikely(rlen == 0)) {
		mesg(context, LOG_ERR, "Empty read from %s/%s", task_path, context->path);
		goto close;
	}

	if (unlikely(thread->comm[rlen - 1] != '\n')) {
		if ((size_t) rlen == sizeof thread->comm) {
			mesg(context, LOG_ERR, "Insufficient buffer size of %zu bytes", sizeof thread->comm);
		} else {
			mesg(context, LOG_ERR, "No terminating new line within %zi bytes read from file", rlen);
		}

		goto exit;
	}

	thread->len = rlen - 1;
	status = true;

close:
	close(fd);

exit:
	return status;
}

[[nodiscard, gnu::pure,
	gnu::nonnull(1, 2), gnu::null_terminated_string_arg(2),
	gnu::access(read_only, 1), gnu::access(read_only, 2)]]
static bool comm_cmp(struct Thread const *restrict thread, char const *restrict str) {
	return thread->len == strlen(str) && !memcmp(thread->comm, str, thread->len);
}

[[nodiscard, gnu::pure,
	gnu::nonnull(1, 2), gnu::null_terminated_string_arg(2),
	gnu::access(read_only, 1), gnu::access(read_only, 2)]]
static bool comm_pre(struct Thread const *restrict thread, char const *restrict str) {
	return thread->len >= strlen(str) && !memcmp(thread->comm, str, strlen(str));
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


[[gnu::nonnull(1, 2), gnu::access(read_only, 1), gnu::access(read_only, 2)]]
static bool thread_sched_rtkit(struct Context const *restrict context, struct Thread const *restrict thread,
                               int current, RtPrio rtprio) {
	if (!context->dbus) {
		goto failure;
	}

	mesg(context, LOG_DEBUG, "Elevating task %.*s [%i] to real‐time priority %" PRI_RTPRIO " via RtKit",
	     (int) thread->len, thread->comm, thread->pid, rtprio);

	if (!(current & SCHED_RESET_ON_FORK)) {
		mesg(context, LOG_DEBUG, "Setting reset‐on‐fork flag on task %.*s [%i]",
		     (int) thread->len, thread->comm, thread->pid);

		struct sched_param param;

		if (unlikely(syscall(SYS_sched_getparam, thread->pid, &param))) {
			mesg(context, LOG_ERR, "Failed to determine scheduling paramaters of task %.*s [%i]",
			     (int) thread->len, thread->comm, thread->pid);
			goto failure;
		}

		if (unlikely(syscall(SYS_sched_setscheduler, thread->pid, current | SCHED_RESET_ON_FORK, &param))) {
			mesg(context, LOG_ERR, "Unable to set reset‐on‐fork flag on task %.*s [%i]: %m",
			     (int) thread->len, thread->comm, thread->pid);
			goto failure;
		}
	}

	if (unlikely(!rtkit_make_realtime(context, thread->pid, rtprio))) {
		mesg(context, LOG_WARN, "Failed to elevate task %.*s [%i] to real‐time priority %" PRI_RTPRIO " via RtKit",
		     (int) thread->len, thread->comm, thread->pid, rtprio);
		goto failure;
	}

	return true;

failure:
	return false;
} 

[[gnu::nonnull(1, 2), gnu::access(read_only, 1), gnu::access(read_only, 2)]]
static bool thread_sched_system(struct Context const *restrict context, struct Thread const *restrict thread,
                                int target, RtPrio rtprio) {
	mesg(context, LOG_DEBUG, "Attempt to change scheduling policy for task %.*s [%i] to %s with priority %" PRI_RTPRIO " directly",
	     (int) thread->len, thread->comm, thread->pid, sched_name(target), rtprio);

	struct sched_param param = {
		.sched_priority = rtprio
	};

	target |= SCHED_RESET_ON_FORK;

	if (unlikely(syscall(SYS_sched_setscheduler, thread->pid, target, &param))) {
		mesg(context, LOG_WARN, "Unable to directly change scheduling policy of task %.*s [%i] to %s with priority %" PRI_RTPRIO ": %m",
		     (int) thread->len, thread->comm, thread->pid, sched_name(target), rtprio);
		goto failure;
	}

	return true;

failure:
	return false;
}

[[gnu::nonnull(1, 2), gnu::access(read_only, 1), gnu::access(read_only, 2)]]
static bool thread_sched(struct Context const *restrict context, struct Thread const *restrict thread, int target, RtPrio rtprio) {
	int current = syscall(SYS_sched_getscheduler, thread->pid);
	if (unlikely(current < 0)) {
		mesg(context, LOG_ERR, "Unable to determine scheduling policy of task %.*s [%i]: %m",
		     (int) thread->len, thread->comm, thread->pid);
		goto failure;
	}

	if ((current & ~SCHED_RESET_ON_FORK) != SCHED_NORMAL) {
		mesg(context, LOG_DEBUG, "Not changing scheduling policy for task %.*s [%i] from %s to %s",
		     (int) thread->len, thread->comm, thread->pid, sched_name(current), sched_name(target));
		goto success;
	}

	mesg(context, LOG_INFO, "Changing scheduling policy for task %.*s [%i] from %s to %s with priority %" PRI_RTPRIO,
	     (int) thread->len, thread->comm, thread->pid, sched_name(current), sched_name(target), rtprio);

	if (!thread_sched_system(context, thread, target, rtprio)) {
		if (target != SCHED_RR || !thread_sched_rtkit(context, thread, current, rtprio)) {
			mesg(context, LOG_ERR, "Failed to change scheduling policy for task %.*s [%i] from %s to %s with priority %" PRI_RTPRIO,
			     (int) thread->len, thread->comm, thread->pid, sched_name(current), sched_name(target), rtprio);
			goto failure;
		}
	}

success:
	return true;

failure:
	return false;
}

[[gnu::nonnull(1, 2), gnu::access(read_only, 1), gnu::access(read_only, 2)]]
static bool thread_renice(struct Context const *restrict context, struct Thread const *restrict thread, Nice target) {
	errno = 0;
	Nice current = getpriority(PRIO_PROCESS, thread->pid);
	if (unlikely(errno)) {
		mesg(context, LOG_ERR, "Unable to determine nice level of task %.*s [%i]", (int) thread->len, thread->comm, thread->pid);
		goto failure;
	}

	if (current <= target) {
		mesg(context, LOG_DEBUG, "Not changing nice level of task %.*s [%i] from %" PRI_NICE " to %" PRI_NICE,
		     (int) thread->len, thread->comm, thread->pid, current, target);
		goto success;
	}

	mesg(context, LOG_INFO, "Changing nice level of task %.*s [%i] from %" PRI_NICE " to %" PRI_NICE,
	     (int) thread->len, thread->comm, thread->pid, current, target);

	if (setpriority(PRIO_PROCESS, thread->pid, target)) {
		mesg(context, LOG_WARN, "Unable to directly change nice level of task %.*s [%i] to %" PRI_NICE ": %m",
		     (int) thread->len, thread->comm, thread->pid, target);

	mesg(context, LOG_DEBUG, "Changing nice level of task %.*s [%i] to %" PRI_NICE " via RtKit",
	     (int) thread->len, thread->comm, thread->pid, target);

		if (!rtkit_renice(context, thread->pid, target)) {
			mesg(context, LOG_ERR, "Failed to change nice level for task %.*s [%i] from %" PRI_NICE " to %" PRI_NICE,
			     (int) thread->len, thread->comm, thread->pid, current, target);
			goto failure;
		}
	}

success:
	return true;

failure:
	return false;
}

[[gnu::nonnull(1), gnu::access(read_only, 1)]]
static bool elevate_threads(struct Context *restrict context) {
	bool status = false;
	DIR *dir;

	{
		int fd = fcntl(context->proc, F_DUPFD_CLOEXEC);
		if (unlikely(fd < 0)) {
			mesg(context, LOG_ERR, "Failed to duplicate %s [%i] file descriptor: %m", task_path, fd);
			goto exit;
		}

		dir = fdopendir(fd);
		if (unlikely(!dir)) {
			mesg(context, LOG_ERR, "Failed to create stdio file handle from %s [%i] file descriptor: %m", task_path, fd);
			close(fd);
			goto exit;
		}
	}

	errno = 0;
	struct dirent *ent;
	while ((ent = readdir(dir))) {
		// skip non‐numeric entries
		for (size_t iter = 0; ent->d_name[iter] != '\0'; ++iter) {
			if (!isdigit(ent->d_name[iter])) {
				goto loop;
			}
		}

		struct Thread thread;

		thread.pid = atoi(ent->d_name);
		assert(thread.pid >= 0);

		if (unlikely(!thread_comm(context, &thread))) {
			mesg(context, LOG_ERR, "Failed to determine command name for thread %i", thread.pid);
			goto loop;
		}

		Nice nice = NICE_INV;
		int policy = SCHED_NORMAL;
		RtPrio rtprio = RTPRIO_INV;

		if (comm_cmp(&thread, "mpv/ao/pipewire") || comm_pre(&thread, "data-loop.")) {
			// audio output: real‐time policy and maximum priority
			policy = SCHED_RR;
			rtprio = context->rtprio_max;
		} else if (comm_cmp(&thread, "vo")) {
			// video output: real‐time scheduling and next lower real‐time priority
			policy = SCHED_RR;
			rtprio = rtprio_sub(context->rtprio_max, RTPRIO_C(1));
		} else if (comm_cmp(&thread, "terminal/input") || comm_pre(&thread, "ipc/") || comm_cmp(&thread, "cplugin/mpris")) {
			// terminal input and IPC: real‐time scheduling and next lower real‐time priority
			policy = SCHED_RR;
			rtprio = rtprio_sub(context->rtprio_max, RTPRIO_C(2));
		} else if (comm_cmp(&thread, "demux") || comm_pre(&thread, "av:")) {
			// demuxing and decoding: batch scheduling and minimum nice level
			nice = context->nice_min;
			policy = SCHED_BATCH;			
		} else if (comm_pre(&thread, "mpv:disk$")) {
			// disk input: batch scheduling and next higher nice level
			nice = nice_add(context->nice_min, NICE_C(1));
			policy = SCHED_BATCH;
		} else {
			mesg(context, LOG_DEBUG, "Ignoring unknown task %.*s [%i]", (int) thread.len, thread.comm, thread.pid);
			goto loop;
		}

		if (nice != NICE_INV) {
			if (!thread_renice(context, &thread, nice)) {
				goto loop;
			}
		}

		if (policy != SCHED_NORMAL) {
			if (!thread_sched(context, &thread, policy, rtprio)) {
				goto loop;
			}
		}

loop:
		// Reset errno to distinguish end‐of‐directory condition from errors
		errno = 0;
	}

	if (unlikely(errno)) {
		mesg(context, LOG_ERR, "Failed to read directory entry from %s [%p]): %m", task_path, dir);
		goto closedir;
	}

	status = true;

closedir:
	closedir(dir);
	
exit:
	return status;
}

[[gnu::nonnull(1, 2), gnu::access(write_only, 1), gnu::access(none, 2)]]
static bool context_init(struct Context *restrict context, struct mpv_handle *restrict mpv) {
	context->mpv = mpv;
	context->tty = isatty(2);

	// Fall back to stderr during initialisation
	context->err = stderr;

	{
		int fd = fcntl(2, F_DUPFD_CLOEXEC);
		if (unlikely(fd < 0)) {
			mesg(context, LOG_CRIT, "Failed to duplicate standard error file descriptor [2]: %m");
			goto failure;
		}

		FILE *err = fdopen(fd, "w");
		if (unlikely(!err)) {
		  mesg(context, LOG_CRIT, "Failed to create stdio file handle from duplicated standard error file descriptor [%i]", fd);
			close(fd);
		  goto failure;
		}

		context->err = err;
	}

	if (unlikely(setvbuf(context->err, context->buf, _IOLBF, sizeof context->buf))) {
		mesg(context, LOG_CRIT, "Failed to set up stdio buffer for duplicated standard error file handle [%p]: %m", context->err);
		goto fclose;
	}

	context->proc = open(task_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (unlikely(context->proc < 0)) {
		mesg(context, LOG_CRIT, "Failed to open task directory at %s: %m", task_path);
		goto fclose;
	}

	DBusError error = DBUS_ERROR_INIT;
	context->dbus = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	if (unlikely(!context->dbus)) {
		mesg(context, LOG_WARN, "Unable to connect to D-Bus system bus: %s", error.message);
	}

	context->nice_min = NICE_C(-15);
	context->rtprio_max = RTPRIO_C(20);

	return true;

fclose:
	fclose(context->err);

failure:
	/* memset(context, 0, sizeof *context); */
	return false;
}

[[gnu::nonnull(1), gnu::access(read_only, 1)]]
static void context_destroy(struct Context /* const */ *restrict context) {
	close(context->proc);

	if (context->dbus) {
		dbus_connection_unref(context->dbus);
	}

	fclose(context->err);
	/* memset(context, 0, sizeof *context); */
}

[[nodiscard, gnu::const]]
uint_fast16_t major(uint_fast32_t version) {
	return (uint_fast16_t) (version >> 16);
}

[[nodiscard, gnu::const]]
uint_fast16_t minor(uint_fast32_t version) {
	return (uint_fast16_t) (version & ((UINT32_C(1) << 16) - UINT32_C(1)));
}

[[gnu::visibility("default"), gnu::nonnull(1)]]
int mpv_open_cplugin(struct mpv_handle *restrict mpv) {
	struct Context context;

	if (unlikely(!context_init(&context, mpv))) {
		goto failure;
	}

	if (major(MPV_CLIENT_API_VERSION) != major(mpv_client_api_version())) {
		mesg(&context, LOG_CRIT, "Incompatible mpv client API versions: "
			"Built with version %" PRIuFAST16 ".%" PRIuFAST16 ", "
			"but run with version %" PRIuFAST16 ".%" PRIuFAST16,
			major(MPV_CLIENT_API_VERSION), minor(MPV_CLIENT_API_VERSION),
			major(mpv_client_api_version()), minor(mpv_client_api_version()));
		goto destroy;
	} else if (minor(MPV_CLIENT_API_VERSION) > minor(mpv_client_api_version())) {
		mesg(&context, LOG_WARN, "Potentially incompatible mpv client API versions: "
			"Built with version %" PRIuFAST16 ".%" PRIuFAST16 ", "
			"but run with version %" PRIuFAST16 ".%" PRIuFAST16,
			major(MPV_CLIENT_API_VERSION), minor(MPV_CLIENT_API_VERSION),
			major(mpv_client_api_version()), minor(mpv_client_api_version()));
	} else {
		mesg(&context, LOG_DEBUG, "mpv client API version %" PRIuFAST16 ".%" PRIuFAST16 " "
		  "(built with %" PRIuFAST16 ".%" PRIuFAST16 ")",
			major(MPV_CLIENT_API_VERSION), minor(MPV_CLIENT_API_VERSION),
			major(mpv_client_api_version()), minor(mpv_client_api_version()));
	}

	{
		uint_fast64_t rttime_max = UINT64_C(20000);

		if (context.dbus) {
			uint_fast64_t rttime_max_rtk = rtkit_rttime_max(&context);
			if (unlikely(rttime_max_rtk >= INT_FAST64_MAX)) {
			  mesg(&context, LOG_WARN, "Unable to determine maximum real‐time period from RtKit");
			} else {
				rttime_max = rttime_max_rtk;
			}
		}

		mesg(&context, LOG_INFO, "Limiting real‐time period to %" PRIuFAST64 " µs", rttime_max);

		struct rlimit rlim = {
		  .rlim_cur = rttime_max,
		  .rlim_max = rttime_max
		};

		if (unlikely(setrlimit(RLIMIT_RTTIME, &rlim))) {
		  mesg(&context, LOG_CRIT, "Failed to limit real‐time period to %" PRIuFAST64 ": %m", rttime_max);
		  goto destroy;
		}
	}

	if (context.dbus) {
		RtPrio rtprio_max = rtkit_realtime_max(&context);
		if (unlikely(!rtprio_valid(rtprio_max))) {
			mesg(&context, LOG_WARN, "Unable to determine maximum real‐time period from RtKit");
		} else {
			context.rtprio_max = rtprio_max;
		}

		Nice nice_min = rtkit_nice_min(&context);
		if (unlikely(!nice_valid(nice_min))) {
			mesg(&context, LOG_CRIT, "Unable to determine minimum nice level from RtKit");
		} else {
			context.nice_min = nice_min;
		}
	}

	mesg(&context, LOG_INFO, "Minimum nice level %" PRI_NICE ", maximum real‐time priority %" PRI_RTPRIO,
	     context.nice_min, context.rtprio_max);

	while (true) {
		struct mpv_event *event = mpv_wait_event(mpv, 0.0);
		assert(event);

		switch (event->event_id) {
		case MPV_EVENT_FILE_LOADED:
		case MPV_EVENT_VIDEO_RECONFIG:
		case MPV_EVENT_AUDIO_RECONFIG:
			if (!elevate_threads(&context)) {
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
