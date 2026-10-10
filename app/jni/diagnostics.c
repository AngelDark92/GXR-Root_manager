#define _GNU_SOURCE
#include <jni.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/futex.h>
#include <linux/sched/types.h>
#include <sys/select.h>

typedef struct {
    char data[65536];
    size_t used;
    bool failed;
} Json;

static void append(Json *json, const char *format, ...) {
    if (json->failed) return;
    va_list arguments;
    va_start(arguments, format);
    int size = vsnprintf(json->data + json->used, sizeof(json->data) - json->used, format, arguments);
    va_end(arguments);
    if (size < 0 || (size_t)size >= sizeof(json->data) - json->used) {
        json->failed = true;
        return;
    }
    json->used += (size_t)size;
}

static void string(Json *json, const char *value) {
    append(json, "\"");
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor; ++cursor) {
        if (*cursor == '"' || *cursor == '\\') append(json, "\\%c", *cursor);
        else if (*cursor < 0x20 || *cursor >= 0x7f) append(json, "\\u%04x", (unsigned int)*cursor);
        else append(json, "%c", *cursor);
    }
    append(json, "\"");
}

static void error(Json *json, const char *operation, int number) {
    append(json, "{\"error\":");
    string(json, operation);
    append(json, ",\"errno\":%d,\"message\":", number);
    string(json, strerror(number));
    append(json, "}");
}

static bool read_text(const char *path, char *buffer, size_t capacity, int *number) {
    int descriptor = open(path, O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) {
        *number = errno;
        return false;
    }
    size_t used = 0;
    while (used < capacity - 1) {
        ssize_t count = read(descriptor, buffer + used, capacity - 1 - used);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) {
            *number = errno;
            close(descriptor);
            return false;
        }
        if (count == 0) break;
        used += (size_t)count;
    }
    close(descriptor);
    if (used == capacity - 1) {
        *number = ENOBUFS;
        return false;
    }
    while (used && (buffer[used - 1] == '\0' || buffer[used - 1] == '\n' || buffer[used - 1] == '\r')) --used;
    if (memchr(buffer, '\0', used) != NULL) {
        *number = EILSEQ;
        return false;
    }
    buffer[used] = '\0';
    *number = 0;
    return true;
}

static void text_observation(Json *json, const char *path, char *buffer, size_t capacity) {
    int number;
    if (read_text(path, buffer, capacity, &number)) {
        append(json, "{\"value\":");
        string(json, buffer);
        append(json, "}");
    } else {
        error(json, "bounded file read unavailable", number);
    }
}

static void status_field(Json *json, const char *status, const char *name) {
    size_t length = strlen(name);
    for (const char *line = status; line && *line;) {
        if (strncmp(line, name, length) == 0 && line[length] == ':') {
            const char *value = line + length + 1;
            while (*value == ' ' || *value == '\t') ++value;
            errno = 0;
            char *end;
            unsigned long number = strtoul(value, &end, 10);
            while (*end == ' ' || *end == '\t' || *end == '\r') ++end;
            if (*value < '0' || *value > '9' || errno || (*end != '\n' && *end != '\0')) {
                error(json, "status field malformed", EINVAL);
            } else {
                append(json, "{\"value\":%lu}", number);
            }
            return;
        }
        line = strchr(line, '\n');
        if (line) ++line;
    }
    error(json, "status field unavailable", ENOENT);
}

static void limit_value(Json *json, rlim_t value) {
    if (value == RLIM_INFINITY) string(json, "infinity");
    else append(json, "\"%llu\"", (unsigned long long)value);
}

static void limit(Json *json, int resource) {
    struct rlimit value;
    if (getrlimit(resource, &value) != 0) {
        error(json, "getrlimit unavailable", errno);
        return;
    }
    append(json, "{\"soft\":");
    limit_value(json, value.rlim_cur);
    append(json, ",\"hard\":");
    limit_value(json, value.rlim_max);
    append(json, "}");
}

static void probe(Json *json, const char *path, int flags) {
    int descriptor = open(path, flags | O_CLOEXEC);
    int number = descriptor < 0 ? errno : 0;
    if (descriptor >= 0) close(descriptor);
    append(json, "{\"path\":");
    string(json, path);
    append(json, ",\"open_allowed\":%s,\"errno\":%d,\"access\":", number == 0 ? "true" : "false", number);
    string(json, (flags & O_RDWR) == O_RDWR ? "read_write" : (flags & O_WRONLY) ? "write" : "read");
    append(json, ",\"nonblocking\":%s,\"observation\":", flags & O_NONBLOCK ? "true" : "false");
    string(json, "Opened and closed only; no data read, write or ioctl; positive open does not establish feasibility");
    append(json, "}");
}

static bool valid_boot_id(const char *value) {
    if (strlen(value) != 36) return false;
    for (size_t index = 0; index < 36; ++index) {
        if (index == 8 || index == 13 || index == 18 || index == 23) {
            if (value[index] != '-') return false;
        } else if (!((value[index] >= '0' && value[index] <= '9') ||
                     (value[index] >= 'a' && value[index] <= 'f') ||
                     (value[index] >= 'A' && value[index] <= 'F'))) return false;
    }
    return true;
}

static void property_observation(Json *json, const char *name) {
    char value[PROP_VALUE_MAX] = {0};
    int length = __system_property_get(name, value);
    string(json, name);
    append(json, ":");
    if (length <= 0) error(json, "property absent or inaccessible", ENOENT);
    else {
        append(json, "{\"value\":");
        string(json, value);
        append(json, "}");
    }
}

/* ---- 0.2.0 feasibility probes ------------------------------------------------
 * All read-only or self-contained. No tracefs writes, no raw trace reads, no
 * vulnerability trigger, no allocation spray, no root commands, no SELinux
 * change. Each probe reports the kernel's own errno answer for the app context.
 * Positive results do not establish exploit feasibility. */

/* Run fn() in a forked, wait-collected child so a blocking or fatal syscall
 * cannot hang or kill the app. Every child body must _exit() with its answer
 * encoded in the exit code: 0 = allowed, 1 = syscall failed without errno,
 * 2..127 = errno, 124..126 = probe harness limits, signal = killed. */
static void probe_in_child(Json *json, const char *name, void (*fn)(void)) {
    fflush(NULL);
    pid_t child = fork();
    if (child == 0) {
        /* child */
        errno = 0;
        fn();
        _exit(0);
    }
    int status = 0;
    int fork_errno = errno;
    append(json, "{\"name\":");
    string(json, name);
    if (child < 0) {
        append(json, ",\"fork_errno\":%d}", fork_errno);
        return;
    }
    int reaped = waitpid(child, &status, 0);
    if (reaped < 0) {
        append(json, ",\"wait_errno\":%d}", errno);
        return;
    }
    if (WIFSIGNALED(status)) {
        append(json, ",\"signal\":%d}", WTERMSIG(status));
        return;
    }
    int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    append(json, ",\"exit\":%d}", exit_code);
}

/* Child bodies. Each records its syscall errno to the process exit code so the
 * parent can report the kernel's exact answer without sharing memory. */

static void child_futex_lock_pi(void) {
    uint32_t word = 0;
    errno = 0;
    long ret = syscall(SYS_futex, &word, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
    if (ret == 0) {
        syscall(SYS_futex, &word, FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
        _exit(0);
    }
    _exit(errno == 0 ? 1 : (errno > 127 ? 127 : errno));
}

static void child_futex_wait_requeue_pi(void) {
    uint32_t wait_word = 0;
    uint32_t target_word = 0;
    errno = 0;
    /* Bounded: timeout 0 means no blocking wait, returns EAGAIN or EWOULDBLOCK
     * when nothing to wait on — kernel access policy still fully exercised. */
    struct timespec zero = {0, 0};
    long ret = syscall(SYS_futex, &wait_word, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 0, &zero, &target_word, 0);
    if (ret >= 0) _exit(0);
    _exit(errno == 0 ? 1 : (errno > 127 ? 127 : errno));
}

static void child_futex_cmp_requeue_pi(void) {
    uint32_t wait_word = 0;
    uint32_t target_word = 0;
    errno = 0;
    long ret = syscall(SYS_futex, &wait_word, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, (void *)(intptr_t)1, &target_word, 0);
    if (ret >= 0) _exit(0);
    _exit(errno == 0 ? 1 : (errno > 127 ? 127 : errno));
}

static void child_pselect6(void) {
    fd_set in, out, ex;
    FD_ZERO(&in); FD_ZERO(&out); FD_ZERO(&ex);
    struct timespec zero = {0, 0};
    errno = 0;
    int ret = pselect(0, &in, &out, &ex, &zero, NULL);
    /* ret >= 0 (here 0) is success regardless of errno residue; report 0. */
    if (ret >= 0) _exit(0);
    _exit(errno == 0 ? 1 : (errno > 127 ? 127 : errno));
}

static void child_pipe_dupfd(void) {
    int pipefd[2] = {-1, -1};
    errno = 0;
    if (pipe(pipefd) != 0) _exit(errno == 0 ? 1 : (errno > 127 ? 127 : errno));
    errno = 0;
    int dupfd = fcntl(pipefd[0], F_DUPFD, 208);
    int number = errno;
    if (dupfd >= 0) close(dupfd);
    close(pipefd[0]);
    close(pipefd[1]);
    _exit(dupfd >= 0 ? 0 : (number == 0 ? 1 : (number > 127 ? 127 : number)));
}

static void child_proc_child_mem(void) {
    fflush(NULL);
    pid_t child = fork();
    if (child == 0) {
        pause();
        _exit(0);
    }
    if (child < 0) _exit(125);
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", child);
    errno = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    int number = errno;
    if (fd >= 0) close(fd);
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    _exit(fd >= 0 ? 0 : (number == 0 ? 1 : (number > 127 ? 127 : number)));
}

static void child_posix_openpt(void) {
    errno = 0;
    int master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    int number = errno;
    if (master >= 0) close(master);
    _exit(master >= 0 ? 0 : (number == 0 ? 1 : (number > 127 ? 127 : number)));
}

static void child_sched_setattr_tid(void) {
    /* sched_setattr on our own thread: unprivileged use, no permission needed
     * for a nice value. Mirrors the exploit's consumer-thread lowering. Uses
     * the kernel struct from <linux/sched/types.h>; policy SCHED_OTHER(0),
     * nice 0, flags 0 is a no-op setting that still exercises the syscall. */
    struct sched_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);
    attr.sched_policy = SCHED_OTHER;
    attr.sched_nice = 0;
    errno = 0;
    long ret = syscall(SYS_sched_setattr, 0, &attr, 0);
    if (ret == 0) _exit(0);
    _exit(errno == 0 ? 1 : (errno > 127 ? 127 : errno));
}

static void child_socketpair_unix_stream(void) {
    errno = 0;
    int fds[2] = {-1, -1};
    long ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
    int number = errno;
    if (ret == 0) { close(fds[0]); close(fds[1]); }
    _exit(ret == 0 ? 0 : (number == 0 ? 1 : (number > 127 ? 127 : number)));
}

static void child_socket_unix_dgram(void) {
    errno = 0;
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    int number = errno;
    if (fd >= 0) close(fd);
    _exit(fd >= 0 ? 0 : (number == 0 ? 1 : (number > 127 ? 127 : number)));
}

static void child_exec_self_lib(void) {
    /* Exec OUR packaged library from the app's nativeLibraryDir: tests
     * untrusted_app exec policy for packaged native code (the W^X question
     * for a future exploit runner). A shared object usually fails with
     * ENOEXEC; EACCES would mean exec of packaged native code is blocked.
     * Find our own .so via /proc/self/maps, not /proc/self/exe (that is
     * app_process64 for an app process). */
    char so_path[PATH_MAX] = {0};
    int maps = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (maps < 0) _exit(124);
    char line[4096];
    ssize_t used = 0;
    for (;;) {
        ssize_t n = read(maps, line + used, 1);
        if (n <= 0) break;
        if (line[used] != '\n') {
            if (used < (ssize_t)sizeof(line) - 1) used++;
            continue;
        }
        line[used] = '\0';
        if (so_path[0] == '\0') {
            char *hit = strstr(line, "libgxr_diagnostics.so");
            if (hit) {
                char *path_start = strchr(line, '/');
                if (path_start) {
                    size_t end = strlen(path_start);
                    while (end > 0 && path_start[end - 1] != '\n') {
                        if (path_start[end - 1] == ' ' || path_start[end - 1] == '\t' || path_start[end - 1] == '\r') end--;
                        else break;
                    }
                    size_t limit = end < sizeof(so_path) - 1 ? end : sizeof(so_path) - 1;
                    memcpy(so_path, path_start, limit);
                    so_path[limit] = '\0';
                }
            }
        }
        used = 0;
    }
    close(maps);
    if (so_path[0] == '\0') _exit(123);
    errno = 0;
    char *const argv[] = {so_path, NULL};
    alarm(5); /* bound the replacement process if exec somehow succeeds */
    execve(so_path, argv, NULL);
    _exit(errno == 0 ? 1 : (errno > 127 ? 127 : errno));
}

static void child_readlink_self_exe(void) {
    char path[PATH_MAX];
    errno = 0;
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    _exit(len < 0 ? (errno == 0 ? 1 : (errno > 127 ? 127 : errno)) : 0);
}

static void child_ashmem_boot_path(void) {
    char boot_id[128] = {0};
    int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
    if (fd < 0) _exit(125);
    ssize_t n = read(fd, boot_id, sizeof(boot_id) - 1);
    close(fd);
    if (n <= 0) _exit(124);
    boot_id[n] = '\0';
    /* trim trailing newline from the boot ID read */
    boot_id[strcspn(boot_id, "\r\n")] = '\0';
    char path[160];
    snprintf(path, sizeof(path), "/dev/ashmem%s", boot_id);
    errno = 0;
    int ashmem_fd = open(path, O_RDWR | O_CLOEXEC);
    int number = errno;
    if (ashmem_fd >= 0) close(ashmem_fd);
    _exit(ashmem_fd >= 0 ? 0 : (number == 0 ? 1 : (number > 127 ? 127 : number)));
}

/* 0.2.1 probes: Route A (perf_event_open KASLR leak) and Route C (fork-hold
 * spray without /proc/<child>/mem). Read-only; no vulnerability trigger. */

static void child_perf_event_open_hw(void) {
    /* q3slide.c tier-2: hardware PMU CPU_CYCLES with exclude_user=1. If this
     * opens, kernel callchain samples are reachable from the app and the
     * IonStackQuest3 leak route is viable. */
    struct perf_event_attr {
        uint32_t type;
        uint32_t size;
        uint64_t config;
        union { uint64_t sample_period; uint64_t sample_freq; };
        uint64_t sample_type;
        uint64_t read_format;
        uint32_t disabled : 1, inherit : 1, exclusive : 1;
        uint32_t exclude_user : 1, exclude_kernel : 1, exclude_hv : 1;
        uint32_t exclude_idle : 1, mmap : 1, comm : 1, freq : 1;
        uint32_t inherit_stat : 1, precise_ip : 2, mmap_data : 1;
        uint32_t sample_id_all : 1, exclude_host : 1, exclude_guest : 1;
        uint32_t exclude_callchain_kernel : 1, exclude_callchain_user : 1;
        uint32_t mmap2 : 1, comm_exec : 1, use_clockid : 1, context_switch : 1;
        uint32_t write_backward : 1, namespaces : 1, cgroup : 1, text_poke : 1;
        uint32_t buildid : 1, inherit_thread : 1, remove_on_exec : 1;
        uint32_t sigtrap : 1;
        uint32_t __reserved_1 : 26;
        union { uint32_t wakeup_events; uint32_t wakeup_watermark; };
        uint32_t bp_type;
        union { uint64_t bp_addr; uint64_t config1; };
        union { uint64_t bp_len; uint64_t config2; };
        uint64_t branch_sample_type;
        uint64_t sample_regs_user;
        uint32_t sample_stack_user;
        uint32_t clockid;
        uint64_t sample_regs_intr;
        uint64_t aux_watermark;
        uint32_t sample_max_stack;
        uint32_t __reserved_2;
        uint64_t aux_sample_size;
        uint32_t __reserved_3;
        uint64_t sig_data;
    };
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = 0 /* PERF_TYPE_HARDWARE */;
    attr.size = sizeof(attr);
    attr.config = 0 /* PERF_COUNT_HW_CPU_CYCLES */;
    attr.sample_period = 50000;
    attr.sample_type = (1ULL << 0) | (1ULL << 5) /* PERF_SAMPLE_IP | PERF_SAMPLE_CALLCHAIN */;
    attr.disabled = 1;
    attr.exclude_hv = 1;
    attr.exclude_user = 1;
    attr.sample_max_stack = 24;
    errno = 0;
    long fd = syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
    if (fd >= 0) {
        close((int)fd);
        _exit(0);
    }
    _exit(errno == 0 ? 1 : (errno > 127 ? 127 : errno));
}

static void child_perf_event_open_sw(void) {
    /* q3slide.c fallback: software CPU clock, kernel+user callchain. */
    struct perf_event_attr {
        uint32_t type;
        uint32_t size;
        uint64_t config;
        uint64_t sample_period;
        uint64_t sample_type;
        uint64_t read_format;
        uint32_t flags1;   /* bitfield dword: disabled=bit0, exclude_hv=bit5 */
        uint32_t wakeup_events;
        uint32_t bp_type;
        uint64_t config1;
        uint64_t config2;
        uint64_t branch_sample_type;
        uint64_t sample_regs_user;
        uint32_t sample_stack_user;
        uint32_t clockid;
        uint64_t sample_regs_intr;
        uint64_t aux_watermark;
        uint32_t sample_max_stack;
        uint32_t reserved;
    };
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = 1 /* PERF_TYPE_SOFTWARE */;
    attr.size = sizeof(attr);
    attr.config = 5 /* PERF_COUNT_SW_CPU_CLOCK */;
    attr.sample_period = 100000;
    attr.sample_type = (1ULL << 0) | (1ULL << 5);
    attr.flags1 = (1u << 0) /* disabled */ | (1u << 5) /* exclude_hv */;
    attr.sample_max_stack = 24;
    errno = 0;
    long fd = syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
    if (fd >= 0) {
        close((int)fd);
        _exit(0);
    }
    _exit(errno == 0 ? 1 : (errno > 127 ? 127 : errno));
}

static void child_perf_event_open_sw_page_faults(void) {
    /* q3slide.c fallback: software page faults (user faults still get a
     * kernel callchain through the fault handler). */
    struct perf_event_attr {
        uint32_t type;
        uint32_t size;
        uint64_t config;
        uint64_t sample_period;
        uint64_t sample_type;
        uint64_t read_format;
        uint32_t flags1;   /* bitfield dword: disabled=bit0, exclude_hv=bit5 */
        uint32_t wakeup_events;
        uint32_t bp_type;
        uint64_t config1;
        uint64_t config2;
        uint64_t branch_sample_type;
        uint64_t sample_regs_user;
        uint32_t sample_stack_user;
        uint32_t clockid;
        uint64_t sample_regs_intr;
        uint64_t aux_watermark;
        uint32_t sample_max_stack;
        uint32_t reserved;
    };
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = 1 /* PERF_TYPE_SOFTWARE */;
    attr.size = sizeof(attr);
    attr.config = 3 /* PERF_COUNT_SW_PAGE_FAULTS */;
    attr.sample_period = 1;
    attr.sample_type = (1ULL << 0) | (1ULL << 5);
    attr.flags1 = (1u << 0) /* disabled */ | (1u << 5) /* exclude_hv */;
    attr.sample_max_stack = 24;
    errno = 0;
    long fd = syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
    if (fd >= 0) {
        close((int)fd);
        _exit(0);
    }
    _exit(errno == 0 ? 1 : (errno > 127 ? 127 : errno));
}

static void child_fork_hold_pause(void) {
    /* Route C: fork a child that pauses (alive), verify it stays reapable and
     * killable by the app. Alive children keep their mm_struct allocated, so
     * the spray does not need /proc/<child>/mem fds. */
    pid_t child = fork();
    if (child == 0) {
        /* grandchild: stay alive */
        pause();
        _exit(0);
    }
    if (child < 0) _exit(errno == 0 ? 1 : (errno > 127 ? 127 : errno));
    errno = 0;
    int alive = kill(child, 0);
    int kill_errno = errno;
    int killed = kill(child, SIGKILL);
    (void)killed;
    int status = 0;
    waitpid(child, &status, 0);
    _exit(alive == 0 ? 0 : (kill_errno == 0 ? 1 : (kill_errno > 127 ? 127 : kill_errno)));
}

static void probe_one(Json *json, const char *name, void (*fn)(void)) {
    probe_in_child(json, name, fn);
}

JNIEXPORT jstring JNICALL Java_dev_galaxyxr_rootmanager_NativeDiagnostics_inspect(JNIEnv *environment, jclass type) {
    (void)type;
    Json json = {0};
    char buffer[8192];
    char boot_id[128] = {0};
    int number;
    append(&json, "{\"uid\":%lu,\"effective_uid\":%lu,\"uname\":", (unsigned long)getuid(), (unsigned long)geteuid());
    struct utsname identity;
    if (uname(&identity) != 0) error(&json, "uname unavailable", errno);
    else {
        append(&json, "{\"release\":");
        string(&json, identity.release);
        append(&json, ",\"version\":");
        string(&json, identity.version);
        append(&json, ",\"machine\":");
        string(&json, identity.machine);
        append(&json, "}");
    }
    append(&json, ",\"page_size\":");
    errno = 0;
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) error(&json, "page size unavailable", errno ? errno : EINVAL);
    else append(&json, "%ld", page_size);
    append(&json, ",\"selinux_context\":");
    text_observation(&json, "/proc/self/attr/current", buffer, 1024);
    append(&json, ",\"selinux_enforcing\":");
    text_observation(&json, "/sys/fs/selinux/enforce", buffer, 128);
    append(&json, ",\"boot_id\":");
    bool boot_read = read_text("/proc/sys/kernel/random/boot_id", boot_id, sizeof(boot_id), &number);
    if (boot_read) {
        append(&json, "{\"value\":");
        string(&json, boot_id);
        append(&json, "}");
    } else error(&json, "bounded boot ID read unavailable", number);
    append(&json, ",\"read_only_properties\":{");
    const char *properties[] = {
        "ro.boot.slot_suffix", "ro.boot.verifiedbootstate", "ro.boot.vbmeta.device_state",
        "ro.build.version.security_patch", "ro.product.cpu.abilist32", "ro.virtual_ab.enabled"
    };
    for (size_t index = 0; index < sizeof(properties) / sizeof(properties[0]); ++index) {
        if (index) append(&json, ",");
        property_observation(&json, properties[index]);
    }
    append(&json, "}");
    append(&json, ",\"no_new_privs\":");
    bool status_read = read_text("/proc/self/status", buffer, sizeof(buffer), &number);
    if (status_read) status_field(&json, buffer, "NoNewPrivs");
    else error(&json, "bounded process status read unavailable", number);
    append(&json, ",\"seccomp\":");
    if (status_read) status_field(&json, buffer, "Seccomp");
    else error(&json, "bounded process status read unavailable", number);
    append(&json, ",\"rlimit_nofile\":");
    limit(&json, RLIMIT_NOFILE);
    append(&json, ",\"rlimit_nproc\":");
    limit(&json, RLIMIT_NPROC);
    append(&json, ",\"allowed_cpu_ids\":");
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    if (sched_getaffinity(0, sizeof(cpus), &cpus) != 0) error(&json, "sched_getaffinity unavailable", errno);
    else {
        append(&json, "[");
        bool first = true;
        for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) if (CPU_ISSET(cpu, &cpus)) {
            append(&json, "%s%d", first ? "" : ",", cpu);
            first = false;
        }
        append(&json, "]");
    }
    append(&json, ",\"permission_probes\":[");
    probe(&json, "/sys/kernel/tracing/tracing_on", O_WRONLY);
    append(&json, ",");
    probe(&json, "/sys/kernel/tracing/events/sched/sched_blocked_reason/enable", O_WRONLY);
    append(&json, ",");
    probe(&json, "/sys/kernel/tracing/trace", O_WRONLY);
    append(&json, ",");
    probe(&json, "/sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw", O_RDONLY | O_NONBLOCK);
    append(&json, ",");
    probe(&json, "/dev/ashmem", O_RDWR);
    if (boot_read && valid_boot_id(boot_id)) {
        char path[160];
        snprintf(path, sizeof(path), "/dev/ashmem%s", boot_id);
        append(&json, ",");
        probe(&json, path, O_RDWR);
    }
    append(&json, "],\"boot_specific_ashmem_probe\":");
    string(&json, boot_read ? (valid_boot_id(boot_id) ? "performed" : "skipped: boot ID malformed") : "skipped: boot ID unreadable");
    /* 0.2.0 feasibility probes: one forked child each, no kernel state left
     * behind. Exit 0 = allowed, 1 = syscall failed with errno 0 recorded,
     * 2..127 = errno, 124..126 = probe harness limits, signal = killed. */
    append(&json, ",\"feasibility_probes\":[");
    probe_one(&json, "futex_lock_pi", child_futex_lock_pi);
    append(&json, ",");
    probe_one(&json, "futex_wait_requeue_pi", child_futex_wait_requeue_pi);
    append(&json, ",");
    probe_one(&json, "futex_cmp_requeue_pi", child_futex_cmp_requeue_pi);
    append(&json, ",");
    probe_one(&json, "pselect6", child_pselect6);
    append(&json, ",");
    probe_one(&json, "pipe_f_dupfd", child_pipe_dupfd);
    append(&json, ",");
    probe_one(&json, "proc_child_mem_open", child_proc_child_mem);
    append(&json, ",");
    probe_one(&json, "posix_openpt", child_posix_openpt);
    append(&json, ",");
    probe_one(&json, "sched_setattr", child_sched_setattr_tid);
    append(&json, ",");
    probe_one(&json, "socketpair_unix_stream", child_socketpair_unix_stream);
    append(&json, ",");
    probe_one(&json, "socket_unix_dgram", child_socket_unix_dgram);
    append(&json, ",");
    probe_one(&json, "readlink_self_exe", child_readlink_self_exe);
    append(&json, ",");
    probe_one(&json, "exec_self_lib", child_exec_self_lib);
    append(&json, ",");
    probe_one(&json, "ashmem_boot_path_open", child_ashmem_boot_path);
    append(&json, ",");
    probe_one(&json, "perf_event_open_hw_cpu_cycles", child_perf_event_open_hw);
    append(&json, ",");
    probe_one(&json, "perf_event_open_sw_cpu_clock", child_perf_event_open_sw);
    append(&json, ",");
    probe_one(&json, "perf_event_open_sw_page_faults", child_perf_event_open_sw_page_faults);
    append(&json, ",");
    probe_one(&json, "fork_hold_pause_reapable", child_fork_hold_pause);
    append(&json, "],\"untested\":[\"vulnerability trigger\",\"OTA/snapshot state\",\"allocation keeper lifetime\"]}");
    const char *result = json.failed ? "{\"native_error\":\"Bounded native report capacity exceeded\"}" : json.data;
    return (*environment)->NewStringUTF(environment, result);
}
