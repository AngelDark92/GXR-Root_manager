#define _GNU_SOURCE
/* Standalone read-only client for src/su_daemon.c's native protocol v1.
 * No exploit, daemon, interactive shell, supplied commands or inherited env.
 * UID 0 of the connected kernel-authenticated peer is required before IO.
 */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#ifdef GXR_ANDROID_JNI
#include <jni.h>
#endif

#define OUTPUT_CAP 8192U
#define SU_PROTOCOL_MAGIC 0x53553235U
#define SU_RESPONSE_MAGIC 0x53555235U
#define SU_PASSED_FDS 5U
struct su_tty_state {
  uint8_t has_termios;
  uint8_t has_winsize;
  struct termios termios;
  struct winsize winsize;
};
struct su_request_header {
  uint32_t magic, version, argc, envc;
  uint8_t interactive, reserved[3];
  struct su_tty_state tty;
};
struct su_response { uint32_t magic; int32_t status; };

static const char status_command[] =
    "rc=0; printf 'GXR_UID\\n'; /system/bin/id -u || rc=1; "
    "printf 'GXR_CONTEXT\\n'; /system/bin/id -Z || rc=1; "
    "printf 'GXR_KERNEL\\n'; /system/bin/uname -r || rc=1; "
    "printf 'GXR_BOOT_ID\\n'; /system/bin/cat /proc/sys/kernel/random/boot_id || rc=1; "
    "printf 'GXR_SELINUX\\n'; /system/bin/getenforce || rc=1; exit \"$rc\"";
struct result {
  int peer_known, peer_root, authorized, status_requested, response_known;
  struct ucred peer;
  int32_t protocol_status;
  char out[OUTPUT_CAP], err[OUTPUT_CAP];
  size_t out_len, err_len;
  const char *error;
};

static int64_t now_ms(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return -1;
  return (int64_t)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}
static int wait_ready(int fd, short events, int64_t deadline) {
  for (;;) {
    int64_t current = now_ms();
    if (current < 0 || current >= deadline) { errno = ETIMEDOUT; return 0; }
    struct pollfd p = { .fd = fd, .events = events };
    int n = poll(&p, 1, (int)(deadline - current));
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) { if (!n) errno = ETIMEDOUT; return 0; }
    if (p.revents & (events | POLLHUP)) return 1;
    errno = EIO;
    return 0;
  }
}
static int transfer(int fd, void *buf, size_t count, int writing, int64_t deadline) {
  unsigned char *p = buf;
  while (count) {
    if (!wait_ready(fd, writing ? POLLOUT : POLLIN, deadline)) return 0;
    ssize_t n = writing ? send(fd, p, count, MSG_NOSIGNAL) : recv(fd, p, count, 0);
    if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
    if (n <= 0) { if (!n) errno = ECONNRESET; return 0; }
    p += n;
    count -= (size_t)n;
  }
  return 1;
}
static int send_string(int fd, const char *value, int64_t deadline) {
  uint32_t n = (uint32_t)strlen(value);
  return transfer(fd, &n, sizeof(n), 1, deadline) &&
         transfer(fd, (void *)value, n, 1, deadline);
}
static int send_fds(int conn, const int fds[SU_PASSED_FDS], int64_t deadline) {
  char marker = 'F';
  struct iovec iov = { .iov_base = &marker, .iov_len = 1 };
  union { struct cmsghdr alignment; char bytes[CMSG_SPACE(sizeof(int) * SU_PASSED_FDS)]; } control;
  memset(&control, 0, sizeof(control));
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control.bytes;
  msg.msg_controllen = sizeof(control.bytes);
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(int) * SU_PASSED_FDS);
  memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * SU_PASSED_FDS);
  for (;;) {
    if (!wait_ready(conn, POLLOUT, deadline)) return 0;
    ssize_t n = sendmsg(conn, &msg, MSG_NOSIGNAL);
    if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
    return n == 1;
  }
}
static void close_fd(int *fd) { if (*fd >= 0) { close(*fd); *fd = -1; } }
static int nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL);
  return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}
/* Drain both output pipes concurrently with the final response, avoiding a
 * deadlock when the server waits for a child blocked on a full output pipe. */
static void collect(int conn, int out_fd, int err_fd, int64_t deadline, struct result *r) {
  int out_open = 1, err_open = 1;
  struct su_response response;
  size_t response_len = 0;
  memset(&response, 0, sizeof(response));
  while (out_open || err_open || !r->response_known) {
    int64_t current = now_ms();
    if (current < 0 || current >= deadline) { r->error = "status_timeout"; return; }
    struct pollfd p[3] = {
      { .fd = out_open ? out_fd : -1, .events = POLLIN },
      { .fd = err_open ? err_fd : -1, .events = POLLIN },
      { .fd = r->response_known ? -1 : conn, .events = POLLIN }
    };
    int n = poll(p, 3, (int)(deadline - current));
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) { r->error = n == 0 ? "status_timeout" : "status_poll_failed"; return; }
    for (int i = 0; i < 2; ++i) {
      if (!(p[i].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL))) continue;
      char *output = i ? r->err : r->out;
      size_t *length = i ? &r->err_len : &r->out_len;
      char temporary[1024];
      ssize_t received = read(p[i].fd, temporary, sizeof(temporary));
      if (received < 0 && (errno == EINTR || errno == EAGAIN)) continue;
      if (received < 0) { r->error = "output_read_failed"; return; }
      if (!received) { if (i) err_open = 0; else out_open = 0; continue; }
      if ((size_t)received > OUTPUT_CAP - *length) { r->error = "output_limit"; return; }
      memcpy(output + *length, temporary, (size_t)received);
      *length += (size_t)received;
    }
    if (p[2].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) {
      ssize_t received = recv(conn, (char *)&response + response_len,
                              sizeof(response) - response_len, 0);
      if (received < 0 && (errno == EINTR || errno == EAGAIN)) continue;
      if (received <= 0) { r->error = "response_incomplete"; return; }
      response_len += (size_t)received;
      if (response_len == sizeof(response)) {
        if (response.magic != SU_RESPONSE_MAGIC) { r->error = "response_magic_invalid"; return; }
        r->response_known = 1;
        r->protocol_status = response.status;
      }
    }
  }
  if (r->protocol_status != 0) r->error = "status_command_failed";
}
static void run_status(int conn, int64_t deadline, struct result *r) {
  int out[2] = {-1, -1}, err[2] = {-1, -1}, io[2] = {-1, -1};
  int input = -1, cwd = -1;
  if (pipe2(out, O_CLOEXEC) || pipe2(err, O_CLOEXEC) ||
      socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, io) ||
      !nonblocking(out[0]) || !nonblocking(err[0]) ||
      (input = open("/dev/null", O_RDONLY | O_CLOEXEC)) < 0 ||
      (cwd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)) < 0) {
    r->error = "local_io_setup_failed";
    goto done;
  }
  int fds[SU_PASSED_FDS] = {input, out[1], err[1], cwd, io[1]};
  struct su_request_header header;
  memset(&header, 0, sizeof(header));
  header.magic = SU_PROTOCOL_MAGIC;
  header.version = 1;
  header.argc = 3;
  header.envc = 0;
  if (!send_fds(conn, fds, deadline) ||
      !transfer(conn, &header, sizeof(header), 1, deadline) ||
      !send_string(conn, "sh", deadline) || !send_string(conn, "-c", deadline) ||
      !send_string(conn, status_command, deadline)) {
    r->error = errno == ETIMEDOUT ? "request_timeout" : "request_send_failed";
    goto done;
  }
  r->status_requested = 1;
  close_fd(&out[1]); close_fd(&err[1]); close_fd(&io[1]);
  close_fd(&io[0]); close_fd(&input); close_fd(&cwd);
  collect(conn, out[0], err[0], deadline, r);
done:
  close_fd(&out[0]); close_fd(&out[1]); close_fd(&err[0]); close_fd(&err[1]);
  close_fd(&io[0]); close_fd(&io[1]); close_fd(&input); close_fd(&cwd);
}
static void json_string(FILE *output, const char *value, size_t count) {
  fputc('"', output);
  for (size_t i = 0; i < count; ++i) {
    unsigned char ch = (unsigned char)value[i];
    if (ch == '"' || ch == '\\') { fputc('\\', output); fputc(ch, output); }
    else if (ch >= 32 && ch < 127) fputc(ch, output);
    else fprintf(output, "\\u%04x", ch);
  }
  fputc('"', output);
}
static void emit(FILE *output, const struct result *r, int status) {
  fprintf(output, "{\"proof_format_version\":1,\"legacy_protocol_version\":1,"
         "\"operation\":\"%s\",\"caller_uid\":%lu,\"peer_credentials_available\":%s,"
         "\"root_peer_authenticated\":%s,\"client_authorized\":%s,",
         status ? "status" : "probe", (unsigned long)getuid(),
         r->peer_known ? "true" : "false", r->peer_root ? "true" : "false",
         r->authorized ? "true" : "false");
  if (r->peer_known) fprintf(output, "\"peer_uid\":%lu,\"peer_gid\":%lu,\"peer_pid\":%ld,",
                            (unsigned long)r->peer.uid, (unsigned long)r->peer.gid,
                            (long)r->peer.pid);
  else fprintf(output, "\"peer_uid\":null,\"peer_gid\":null,\"peer_pid\":null,");
  fprintf(output, "\"status_request_sent\":%s,\"request_header_bytes\":%zu,\"protocol_status\":",
         r->status_requested ? "true" : "false", sizeof(struct su_request_header));
  if (r->response_known) fprintf(output, "%d", r->protocol_status); else fprintf(output, "null");
  fprintf(output, ",\"stdout\":"); json_string(output, r->out, r->out_len);
  fprintf(output, ",\"stderr\":"); json_string(output, r->err, r->err_len);
  fprintf(output, ",\"error\":");
  if (r->error) json_string(output, r->error, strlen(r->error)); else fprintf(output, "null");
  fputs("}\n", output);
}
static int verifier_run(int argc, char **argv, FILE *output) {
  struct result r;
  memset(&r, 0, sizeof(r));
  const char *endpoint = "/data/local/tmp/temp_su.sock";
  int status = 0, operation_seen = 0, endpoint_seen = 0, timeout_seen = 0;
  long timeout = 5000;
  int conn = -1;
  for (int i = 1; i < argc; ++i) {
    if ((!strcmp(argv[i], "--probe") || !strcmp(argv[i], "--status")) && !operation_seen) {
      operation_seen = 1;
      status = !strcmp(argv[i], "--status");
    } else if (!strcmp(argv[i], "--endpoint") && !endpoint_seen && i + 1 < argc) {
      endpoint = argv[++i]; endpoint_seen = 1;
    } else if (!strcmp(argv[i], "--timeout-ms") && !timeout_seen && i + 1 < argc) {
      const char *value = argv[++i];
      char *end;
      errno = 0;
      timeout = strtol(value, &end, 10);
      if (errno || end == value || *end || timeout < 100 || timeout > 10000) {
        r.error = "invalid_timeout"; goto done;
      }
      timeout_seen = 1;
    } else { r.error = "invalid_arguments"; goto done; }
  }
  if (!operation_seen) { r.error = "operation_required"; goto done; }
  struct sockaddr_un address;
  memset(&address, 0, sizeof(address));
  size_t endpoint_length = strlen(endpoint);
  int abstract_endpoint = endpoint[0] == '@';
  if ((abstract_endpoint && (endpoint_length <= 1 || endpoint_length > sizeof(address.sun_path))) ||
      (!abstract_endpoint && (endpoint[0] != '/' || endpoint_length >= sizeof(address.sun_path)))) {
    r.error = "invalid_endpoint"; goto done;
  }
  int64_t start = now_ms();
  if (start < 0) { r.error = "monotonic_clock_unavailable"; goto done; }
  int64_t deadline = start + timeout;
  conn = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (conn < 0) { r.error = "socket_failed"; goto done; }
  address.sun_family = AF_UNIX;
  socklen_t address_length = sizeof(address);
  if (abstract_endpoint) {
    memcpy(address.sun_path + 1, endpoint + 1, endpoint_length - 1);
    address_length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + endpoint_length);
  } else {
    memcpy(address.sun_path, endpoint, endpoint_length + 1);
  }
  if (connect(conn, (struct sockaddr *)&address, address_length) != 0) {
    if (errno != EINPROGRESS) { r.error = "connect_failed"; goto done; }
    if (!wait_ready(conn, POLLOUT, deadline)) { r.error = "connect_timeout"; goto done; }
    int error;
    socklen_t length = sizeof(error);
    if (getsockopt(conn, SOL_SOCKET, SO_ERROR, &error, &length) || error) {
      r.error = "connect_failed"; goto done;
    }
  }
  /* This must precede ALL reads or writes on this same connected socket. */
  socklen_t peer_length = sizeof(r.peer);
  if (getsockopt(conn, SOL_SOCKET, SO_PEERCRED, &r.peer, &peer_length) ||
      peer_length != sizeof(r.peer) || r.peer.pid <= 0) {
    r.error = "peer_credentials_unavailable"; goto done;
  }
  r.peer_known = 1;
  if (r.peer.uid != 0) { r.error = "peer_not_root"; goto done; }
  r.peer_root = 1;
  char auth;
  if (!transfer(conn, &auth, 1, 0, deadline)) {
    r.error = errno == ETIMEDOUT ? "authorization_timeout" : "authorization_incomplete";
    goto done;
  }
  if (auth != 'A') { r.error = "client_not_authorized"; goto done; }
  r.authorized = 1;
  if (status) run_status(conn, deadline, &r);
done:
  close_fd(&conn);
  emit(output, &r, status);
  return r.error ? 1 : 0;
}
#ifdef GXR_ANDROID_JNI
JNIEXPORT jstring JNICALL Java_dev_galaxyxr_rootmanager_NativeDiagnostics_verifyRootStatus(
    JNIEnv *env, jclass type) {
  (void)type;
  char *buffer = NULL;
  size_t length = 0;
  FILE *output = open_memstream(&buffer, &length);
  if (!output) {
    return (*env)->NewStringUTF(env, "{\"error\":\"local_report_allocation_failed\"}");
  }
  char *argv[] = {"gxr-bootstrap-verifier", "--status", "--timeout-ms", "1500"};
  verifier_run(4, argv, output);
  int output_failed = ferror(output);
  if (fclose(output) != 0) output_failed = 1;
  jstring result = (*env)->NewStringUTF(env, output_failed || !buffer || !length
      ? "{\"error\":\"local_report_capture_failed\"}" : buffer);
  free(buffer);
  return result;
}
#else
int main(int argc, char **argv) {
  signal(SIGPIPE, SIG_IGN);
  return verifier_run(argc, argv, stdout);
}
#endif
