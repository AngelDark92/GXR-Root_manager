#define _GNU_SOURCE
/* Bounded negative-authentication fixture. Never run as root, send protocol
 * bytes, execute commands, or unlink a socket. Filesystem sockets are retained
 * as evidence in a caller-owned private directory; abstract sockets use only
 * the dedicated gxr-rm-negative- test namespace. */
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static int64_t monotonic_ms(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return -1;
  return (int64_t)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}

static const char *wait_readable(int fd, int64_t deadline) {
  for (;;) {
    int64_t current = monotonic_ms();
    if (current < 0) return "clock_failed";
    if (current >= deadline) { errno = ETIMEDOUT; return "deadline_expired"; }
    struct pollfd item = {.fd = fd, .events = POLLIN};
    int result = poll(&item, 1, (int)(deadline - current));
    if (result < 0 && errno == EINTR) continue;
    if (result < 0) return "poll_failed";
    if (!result) { errno = ETIMEDOUT; return "deadline_expired"; }
    if (item.revents & POLLNVAL) { errno = EBADF; return "invalid_descriptor"; }
    if (item.revents & (POLLIN | POLLHUP | POLLERR)) return NULL;
    errno = EIO;
    return "unexpected_poll_event";
  }
}

static const char *validate_endpoint(const char *path, uid_t owner) {
  size_t length = strlen(path);
  struct sockaddr_un address;
  if (path[0] == '@') {
    static const char prefix[] = "@gxr-rm-negative-";
    if (length <= sizeof(prefix) - 1 || length > sizeof(address.sun_path) ||
        strncmp(path, prefix, sizeof(prefix) - 1))
      return "abstract_test_namespace_required";
    for (size_t i = sizeof(prefix) - 1; i < length; ++i) {
      unsigned char value = (unsigned char)path[i];
      if (!((value >= 'a' && value <= 'z') ||
            (value >= 'A' && value <= 'Z') ||
            (value >= '0' && value <= '9') || value == '-'))
        return "abstract_test_suffix_invalid";
    }
    return NULL;
  }
  if (!length || path[0] != '/' || length >= sizeof(address.sun_path))
    return "endpoint_invalid";
  char parent[sizeof(address.sun_path)];
  memcpy(parent, path, length + 1);
  char *separator = strrchr(parent, '/');
  if (!separator || separator == parent || !separator[1])
    return "endpoint_parent_invalid";
  *separator = '\0';
  const char *basename = path + (separator - parent) + 1;
  if (!strcmp(basename, ".") || !strcmp(basename, ".."))
    return "endpoint_basename_invalid";
  struct stat info;
  if (lstat(parent, &info) != 0 || !S_ISDIR(info.st_mode) ||
      info.st_uid != owner || (info.st_mode & 0077) != 0)
    return "private_parent_required";
  char canonical[PATH_MAX];
  if (!realpath(parent, canonical) || strcmp(parent, canonical))
    return "canonical_parent_required";
  if (lstat(path, &info) == 0) return "endpoint_already_exists";
  if (errno != ENOENT) return "endpoint_stat_failed";
  return NULL;
}

int main(int argc, char **argv) {
  int listener = -1, connection = -1, passed = 0, no_client_bytes = 1;
  int peer_known = 0;
  int failure_errno = 0;
  struct ucred peer;
  memset(&peer, 0, sizeof(peer));
  uid_t uid = getuid(), effective_uid = geteuid();
  const char *error = NULL;
  errno = 0;
  if (!uid || !effective_uid) { error = "root_runner_forbidden"; goto done; }
  if (uid != effective_uid) { error = "changed_identity_forbidden"; goto done; }
  if (argc != 3 || strcmp(argv[1], "--endpoint")) {
    error = "usage_requires_endpoint"; goto done;
  }
  error = validate_endpoint(argv[2], uid);
  if (error) goto done;
  errno = 0;
  int64_t start = monotonic_ms();
  if (start < 0) { error = "clock_failed"; goto done; }
  int64_t deadline = start + 5000;
  listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (listener < 0) { error = "socket_failed"; goto done; }
  struct sockaddr_un address;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  socklen_t address_length = sizeof(address);
  if (argv[2][0] == '@') {
    size_t endpoint_length = strlen(argv[2]);
    memcpy(address.sun_path + 1, argv[2] + 1, endpoint_length - 1);
    address_length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + endpoint_length);
  } else {
    memcpy(address.sun_path, argv[2], strlen(argv[2]) + 1);
  }
  umask(0077);
  /* bind refuses an existing path atomically; never remove one to retry. */
  if (bind(listener, (struct sockaddr *)&address, address_length) != 0) {
    error = "bind_failed"; goto done;
  }
  if (listen(listener, 1) != 0) { error = "listen_failed"; goto done; }
  if (fputs("READY\n", stderr) == EOF || fflush(stderr) == EOF) {
    error = "ready_output_failed"; goto done;
  }
  for (;;) {
    error = wait_readable(listener, deadline);
    if (error) goto done;
    connection = accept4(listener, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (connection >= 0) break;
    if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
    error = "accept_failed"; goto done;
  }
  close(listener);
  listener = -1;
  errno = 0;
  socklen_t peer_length = sizeof(peer);
  if (getsockopt(connection, SOL_SOCKET, SO_PEERCRED, &peer, &peer_length) != 0 ||
      peer_length != sizeof(peer)) {
    error = "peer_credentials_failed"; goto done;
  }
  peer_known = 1;
  if (peer.uid != uid) { error = "unexpected_client_uid"; goto done; }
  for (;;) {
    error = wait_readable(connection, deadline);
    if (error) goto done;
    unsigned char byte;
    errno = 0;
    ssize_t count = recv(connection, &byte, sizeof(byte), 0);
    if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
      continue;
    if (count < 0) { error = "client_read_failed"; goto done; }
    if (count > 0) {
      no_client_bytes = 0;
      error = "client_sent_bytes_before_rejection";
      goto done;
    }
    passed = 1;
    break;
  }
done:
  failure_errno = error ? errno : 0;
  if (connection >= 0) close(connection);
  if (listener >= 0) close(listener);
  printf("{\"passed\":%s,\"no_client_bytes\":%s,\"server_uid\":%lu,"
         "\"server_effective_uid\":%lu,\"peer_uid\":",
         passed ? "true" : "false", no_client_bytes ? "true" : "false",
         (unsigned long)uid, (unsigned long)effective_uid);
  if (peer_known) printf("%lu", (unsigned long)peer.uid);
  else fputs("null", stdout);
  fputs(",\"error\":", stdout);
  if (error) printf("\"%s\"", error);
  else fputs("null", stdout);
  printf(",\"system_errno\":%d}\n", failure_errno);
  if (fflush(stdout) == EOF) return 2;
  return passed ? 0 : 1;
}
