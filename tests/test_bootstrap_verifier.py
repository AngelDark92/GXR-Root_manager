"""Host-only Linux fake-server proof. Never contacts Android or legacy daemon.

SO_PEERCRED is a Linux/Android facility. Windows/macOS skip explicitly; Linux
tests requiring a root peer skip unless launched by a root host test runner.
"""
import array
import ctypes
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "native" / "bootstrap_verifier.c"
LINUX = sys.platform.startswith("linux") and hasattr(socket, "SO_PEERCRED")


class Termios(ctypes.Structure):
    # glibc Linux termios ABI; synthetic tests compile with the same host libc.
    _fields_ = [("iflag", ctypes.c_uint), ("oflag", ctypes.c_uint),
                ("cflag", ctypes.c_uint), ("lflag", ctypes.c_uint),
                ("line", ctypes.c_ubyte), ("cc", ctypes.c_ubyte * 32),
                ("ispeed", ctypes.c_uint), ("ospeed", ctypes.c_uint)]


class Winsize(ctypes.Structure):
    _fields_ = [("rows", ctypes.c_ushort), ("cols", ctypes.c_ushort),
                ("xpixels", ctypes.c_ushort), ("ypixels", ctypes.c_ushort)]


class Tty(ctypes.Structure):
    _fields_ = [("has_termios", ctypes.c_ubyte), ("has_winsize", ctypes.c_ubyte),
                ("termios", Termios), ("winsize", Winsize)]


class Header(ctypes.Structure):
    _fields_ = [("magic", ctypes.c_uint32), ("version", ctypes.c_uint32),
                ("argc", ctypes.c_uint32), ("envc", ctypes.c_uint32),
                ("interactive", ctypes.c_ubyte), ("reserved", ctypes.c_ubyte * 3),
                ("tty", Tty)]


def exact(conn, size):
    value = b""
    while len(value) < size:
        part = conn.recv(size - len(value))
        if not part:
            raise AssertionError("truncated client request")
        value += part
    return value


@unittest.skipUnless(LINUX, "Linux SO_PEERCRED fake-daemon tests require POSIX Linux")
class BootstrapVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("cc") or shutil.which("gcc")
        if not compiler:
            raise unittest.SkipTest("Host C compiler unavailable")
        cls.build = tempfile.TemporaryDirectory(prefix="gxr-verifier-build-")
        cls.binary = Path(cls.build.name) / "verifier"
        subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-O2", str(SOURCE), "-o", str(cls.binary)],
                       check=True, capture_output=True, timeout=30)
        os.chmod(cls.build.name, 0o755)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def run_client(self, *arguments):
        process = subprocess.run([str(self.binary), *arguments],
                                 capture_output=True, timeout=3, text=True)
        self.assertEqual(process.stderr, "")
        return process.returncode, json.loads(process.stdout)

    def server(self, handler, operation="--probe", timeout="300"):
        with tempfile.TemporaryDirectory(prefix="gxr-verifier-socket-") as folder:
            endpoint = str(Path(folder) / "server.sock")
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(endpoint)
            listener.listen(1)
            listener.settimeout(2)
            errors = []

            def serve():
                try:
                    with listener.accept()[0] as conn:
                        conn.settimeout(2)
                        handler(conn)
                except Exception as error:
                    errors.append(error)
                finally:
                    listener.close()

            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            code, proof = self.run_client(operation, "--endpoint", endpoint,
                                          "--timeout-ms", timeout)
            worker.join(2)
            self.assertFalse(worker.is_alive(), "fake daemon did not finish")
            if errors:
                raise errors[0]
            return code, proof

    def test_rejects_arbitrary_cli_and_invalid_limits(self):
        for args, expected in [(("-c", "id"), "invalid_arguments"),
                               (("--daemon",), "invalid_arguments"),
                               (("--probe", "--status"), "invalid_arguments"),
                               (("--probe", "--timeout-ms", "0"), "invalid_timeout"),
                               (("--probe", "--timeout-ms", "10001"), "invalid_timeout"),
                               (("--probe", "--endpoint", "relative"), "invalid_endpoint"),
                               (("--probe", "--endpoint", "/" + "x" * 108), "invalid_endpoint")]:
            with self.subTest(args=args):
                code, proof = self.run_client(*args)
                self.assertEqual(code, 1)
                self.assertEqual(proof["error"], expected)
                self.assertFalse(proof["status_request_sent"])

    def test_missing_endpoint_reports_machine_readable_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            code, proof = self.run_client("--probe", "--endpoint", str(Path(folder) / "absent"))
        self.assertEqual(code, 1)
        self.assertEqual(proof["error"], "connect_failed")
        self.assertFalse(proof["root_peer_authenticated"])

    def test_nonroot_peer_rejected_before_authorization_or_request(self):
        if os.getuid() != 0:
            def nonroot(conn):
                # No auth is sent: verifier must reject solely from credentials.
                self.assertEqual(conn.recv(1), b"")
            code, proof = self.server(nonroot, "--status")
            self.assertEqual(code, 1)
            self.assertEqual(proof["error"], "peer_not_root")
            self.assertFalse(proof["status_request_sent"])
            return
        # Root runner creates a genuinely unprivileged listener in a child.
        with tempfile.TemporaryDirectory(prefix="gxr-nonroot-") as folder:
            os.chmod(folder, 0o777)
            endpoint = str(Path(folder) / "server.sock")
            child_code = ("import os,socket,sys; os.setgroups([]); os.setgid(65534); "
                          "os.setuid(65534); s=socket.socket(socket.AF_UNIX); "
                          "s.bind(sys.argv[1]); s.listen(1); print('ready',flush=True); "
                          "c,_=s.accept(); c.settimeout(2); "
                          "assert c.recv(1)==b''; c.close(); s.close()")
            process = subprocess.Popen([sys.executable, "-c", child_code, endpoint],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                self.assertEqual(process.stdout.readline().strip(), "ready")
                code, proof = self.run_client("--status", "--endpoint", endpoint)
                _, err = process.communicate(timeout=3)
                self.assertEqual(process.returncode, 0, err)
                self.assertEqual(code, 1)
                self.assertEqual(proof["peer_uid"], 65534)
                self.assertEqual(proof["error"], "peer_not_root")
                self.assertFalse(proof["client_authorized"])
                self.assertFalse(proof["status_request_sent"])
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()

    @unittest.skipUnless(LINUX and os.getuid() == 0, "Root host runner needed for UID-0 synthetic peer")
    def test_authorized_probe_sends_no_protocol_request(self):
        def handler(conn):
            conn.sendall(b"A")
            self.assertEqual(conn.recv(1), b"")
        code, proof = self.server(handler)
        self.assertEqual(code, 0)
        self.assertTrue(proof["root_peer_authenticated"])
        self.assertTrue(proof["client_authorized"])
        self.assertEqual(proof["peer_uid"], 0)
        self.assertFalse(proof["status_request_sent"])
        self.assertIsNone(proof["protocol_status"])

    @unittest.skipUnless(LINUX and os.getuid() == 0, "Root host runner needed for UID-0 synthetic peer")
    def test_invalid_auth_and_auth_timeout_send_no_request(self):
        def invalid(conn):
            conn.sendall(b"D")
            self.assertEqual(conn.recv(1), b"")
        code, proof = self.server(invalid)
        self.assertEqual(code, 1)
        self.assertEqual(proof["error"], "client_not_authorized")

        def stalled(conn):
            self.assertEqual(conn.recv(1), b"")
        code, proof = self.server(stalled, timeout="100")
        self.assertEqual(code, 1)
        self.assertEqual(proof["error"], "authorization_timeout")

    def read_status(self, conn):
        conn.sendall(b"A")
        marker, ancillary, flags, _ = conn.recvmsg(1, socket.CMSG_SPACE(5 * array.array("i").itemsize))
        self.assertEqual(marker, b"F")
        self.assertFalse(flags & socket.MSG_CTRUNC)
        self.assertEqual(len(ancillary), 1)
        self.assertEqual(ancillary[0][:2], (socket.SOL_SOCKET, socket.SCM_RIGHTS))
        fds = array.array("i")
        fds.frombytes(ancillary[0][2])
        self.assertEqual(len(fds), 5)
        try:
            raw = exact(conn, ctypes.sizeof(Header))
            header = Header.from_buffer_copy(raw)
            self.assertEqual((header.magic, header.version, header.argc, header.envc),
                             (0x53553235, 1, 3, 0))
            self.assertEqual(header.interactive, 0)
            self.assertEqual(raw[16:], bytes(len(raw) - 16), "tty/reserved fields must be zero")
            args = []
            for _ in range(header.argc):
                size, = struct.unpack("=I", exact(conn, 4))
                self.assertLess(size, 1024)
                args.append(exact(conn, size).decode("ascii"))
            self.assertEqual(args[:2], ["sh", "-c"])
            self.assertEqual(args[2],
                "rc=0; printf 'GXR_UID\\n'; /system/bin/id -u || rc=1; "
                "printf 'GXR_CONTEXT\\n'; /system/bin/id -Z || rc=1; "
                "printf 'GXR_KERNEL\\n'; /system/bin/uname -r || rc=1; "
                "printf 'GXR_BOOT_ID\\n'; /system/bin/cat /proc/sys/kernel/random/boot_id || rc=1; "
                "printf 'GXR_SELINUX\\n'; /system/bin/getenforce || rc=1; exit \"$rc\"")
            self.assertEqual(os.read(fds[0], 1), b"")
            self.assertTrue(os.path.isdir(f"/proc/self/fd/{fds[3]}"))
            return fds
        except BaseException:
            for fd in fds:
                os.close(fd)
            raise

    @unittest.skipUnless(LINUX and os.getuid() == 0, "Root host runner needed for UID-0 synthetic peer")
    def test_status_wire_format_and_bounded_json_output(self):
        def handler(conn):
            fds = self.read_status(conn)
            try:
                os.write(fds[1], b"GXR_UID\n0\nGXR_CONTEXT\nu:r:kernel:s0\n")
                os.write(fds[2], b'example "stderr"\x00\xff\n')
            finally:
                for fd in fds:
                    os.close(fd)
            response = struct.pack("=Ii", 0x53555235, 0)
            conn.sendall(response[:3])
            conn.sendall(response[3:])
        code, proof = self.server(handler, "--status")
        self.assertEqual(code, 0)
        self.assertEqual(proof["protocol_status"], 0)
        self.assertEqual(proof["request_header_bytes"], ctypes.sizeof(Header))
        self.assertEqual(proof["stderr"], 'example "stderr"\x00\xff\n')
        self.assertTrue(proof["status_request_sent"])

    @unittest.skipUnless(LINUX and os.getuid() == 0, "Root host runner needed for UID-0 synthetic peer")
    def test_status_rejects_overflow_bad_magic_and_failure_status(self):
        for mode, expected in [("overflow", "output_limit"),
                               ("magic", "response_magic_invalid"),
                               ("failure", "status_command_failed"),
                               ("timeout", "status_timeout")]:
            with self.subTest(mode=mode):
                def handler(conn):
                    fds = self.read_status(conn)
                    try:
                        if mode == "overflow":
                            try:
                                os.write(fds[1], b"x" * 9000)
                            except BrokenPipeError:
                                pass
                        elif mode == "timeout":
                            time.sleep(0.2)
                    finally:
                        for fd in fds:
                            os.close(fd)
                    if mode in ("magic", "failure"):
                        conn.sendall(struct.pack("=Ii", 123 if mode == "magic" else 0x53555235,
                                                 7 if mode == "failure" else 0))
                code, proof = self.server(handler, "--status", timeout="100")
                self.assertEqual(code, 1)
                self.assertEqual(proof["error"], expected)
                self.assertLessEqual(len(proof["stdout"]), 8192)


if __name__ == "__main__":
    unittest.main()
