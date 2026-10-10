package dev.galaxyxr.rootmanager;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Local-root engine: drives the proven GhostLock chain through a self-hosted
 * local ADB shell (LADB pattern). No PC and no Shizuku involved.
 *
 * Safety rules enforced here (see docs/BOOTSTRAP-INTEGRATION.md):
 *  - live fingerprint must equal the verified target fingerprint exactly
 *  - at most 1 exploit attempt per boot, latched before launch
 *  - no retry after a partial failure in the same boot
 *  - the exploit process is never killed by this app; the supervisor timeout
 *    is raised high enough that only a genuine hang exceeds it, and a hang is
 *    reported (device may need a manual reboot) instead of force-killed
 */
public final class RootEngine {
    public static final String PAYLOAD_EXPLOIT = "gxr-exploit";
    public static final String PAYLOAD_DAEMON = "gxr-rootd";
    public static final String PAYLOAD_ADB = "libadb.so";
    /**
     * KernelSU module for this kernel build: the fail-open DEFEX build with the __versions
     * section contents zeroed in place (section kept), which is what lets this kernel take
     * it. Loaded with allow_shell=1 so UID 2000 gets su as well. Reproduce with
     * tools/patch_kernelsu_module.py; see
     * builds/gxr-kernel/ksu-probe-20261009/RECEIPT.md.
     */
    public static final String PAYLOAD_KSU = "kernelsu-gxr.ko";
    /**
     * Where to send the owner when the KernelSU module is missing. The module this app
     * loads is BYTE-MODIFIED from the upstream release (vermagic rewritten, __versions
     * contents zeroed), so it must not be sourced from the upstream release page.
     * Point this at the project's own release once the patched module is published.
     */
    public static final String KSU_MODULE_URL = "https://github.com/sarabpal-dev/KernelSU-Next/releases/tag/v3.4.0";
    private static final String REMOTE_DIR = "/data/local/tmp/gxr-root";
    private static final long RUN_DEADLINE_MS = 15 * 60 * 1000L;

    public interface Log {
        void line(String text);
    }

    private final Context context;
    private final SharedPreferences prefs;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private volatile Process shellProcess;
    private String adbSerial;
    private volatile boolean cancelled;
    private java.io.PrintWriter runLogWriter;

    public RootEngine(Context context) {
        this.context = context;
        this.prefs = context.getSharedPreferences("local_root", Context.MODE_PRIVATE);
    }

    public void shutdown() {
        worker.shutdown();
    }

    private File payloadFile(String name) throws IOException {
        /* Shell (UID 2000) cannot read the app's internal filesDir; stage payloads
         * in the app-specific external storage which adb shell can read. */
        File dir = context.getExternalFilesDir("payload");
        if (dir == null) throw new IOException("external storage unavailable");
        if (!dir.isDirectory() && !dir.mkdirs()) throw new IOException("payload dir");
        File out = new File(dir, name);
        if (out.isFile() && out.length() > 0) return out;
        try (InputStream in = context.getAssets().open("payload/" + name);
             FileOutputStream os = new FileOutputStream(out)) {
            byte[] buffer = new byte[65536];
            for (int n; (n = in.read(buffer)) > 0; ) os.write(buffer, 0, n);
            os.getFD().sync();
        }
        // Never keep a stale partial file as a valid payload.
        return out;
    }

    private String adbPath() throws IOException {
        /* The adb binary must be executed from nativeLibraryDir: app-data
         * directories are not executable for untrusted_app (W^X). */
        File adb = new File(context.getApplicationInfo().nativeLibraryDir, PAYLOAD_ADB);
        if (!adb.isFile() || !adb.canExecute()) throw new IOException("adb not in nativeLibraryDir");
        return adb.getAbsolutePath();
    }

    /** Runs one adb command to completion; returns combined output. */
    public String adbOnce(List<String> args, long timeoutMs) throws Exception {
        List<String> command = new ArrayList<>();
        command.add(adbPath());
        command.addAll(args);
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.environment().put("HOME", context.getFilesDir().getAbsolutePath());
        builder.environment().put("ADB_VENDOR_KEYS", "");
        builder.environment().put("ANDROID_DATA", "/data");
        Process process = builder.start();
        String output = readAll(process);
        boolean done = process.waitFor(timeoutMs, TimeUnit.MILLISECONDS);
        if (!done) {
            process.destroy();
            throw new IOException("adb command timeout");
        }
        return output.trim();
    }

    private static String readAll(Process process) throws IOException {
        StringBuilder out = new StringBuilder();
        InputStream stdout = process.getInputStream();
        InputStream stderr = process.getErrorStream();
        byte[] buffer = new byte[4096];
        while (true) {
            boolean progressed = false;
            int n;
            while ((n = stdout.read(buffer)) > 0) {
                out.append(new String(buffer, 0, n, StandardCharsets.UTF_8));
                progressed = true;
            }
            while ((n = stderr.read(buffer)) > 0) {
                out.append(new String(buffer, 0, n, StandardCharsets.UTF_8));
                progressed = true;
            }
            try {
                process.exitValue();
                while ((n = stdout.read(buffer)) > 0) out.append(new String(buffer, 0, n, StandardCharsets.UTF_8));
                while ((n = stderr.read(buffer)) > 0) out.append(new String(buffer, 0, n, StandardCharsets.UTF_8));
                return out.toString();
            } catch (IllegalThreadStateException stillRunning) {
                if (!progressed) {
                    try { Thread.sleep(200); }
                    catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
                }
            }
        }
    }

    /** Pair once with the code from Developer options (one-time per install). */
    public String pair(String host, int pairPort, String code) throws Exception {
        List<String> args = new ArrayList<>();
        args.add("pair");
        args.add(host + ":" + pairPort);
        args.add(code);
        return adbOnce(args, 20000);
    }

    /** Connect to the wireless debugging port. */
    public String connect(String host, int port) throws Exception {
        List<String> args = new ArrayList<>();
        args.add("connect");
        args.add(host + ":" + port);
        return adbOnce(args, 20000);
    }

    public String startServer() throws Exception {
        try { adbOnce(List.of("kill-server"), 10000); } catch (Exception ignored) {}
        return adbOnce(List.of("start-server"), 20000);
    }

    /** Live target gate: exact fingerprint match required. */
    public static List<String> identityProblems(String fingerprint) {
        List<String> problems = new ArrayList<>();
        if (!SafetyPolicy.FINGERPRINT.equals(fingerprint)) {
            problems.add("Live fingerprint does not match the verified target build.");
        }
        return problems;
    }

    private String bootId() throws Exception {
        String id = shellCommand("cat /proc/sys/kernel/random/boot_id", 5000);
        if (id == null || !id.trim().matches("[0-9a-fA-F-]{36}")) throw new IOException("boot id unavailable");
        return id.trim();
    }

    /** Opens a persistent interactive shell for the run; returns its writer. */
    private Process openShell() throws Exception {
        List<String> command = new ArrayList<>();
        command.add(adbPath());
        command.add("shell");
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.environment().put("HOME", context.getFilesDir().getAbsolutePath());
        builder.environment().put("ADB_VENDOR_KEYS", "");
        if (adbSerial != null && !adbSerial.isEmpty()) builder.environment().put("ANDROID_SERIAL", adbSerial);
        Process process = builder.start();
        shellProcess = process;
        return process;
    }

    private String shellCommand(String command, long timeoutMs) throws Exception {
        Process process = openShell();
        try {
            OutputStream stdin = process.getOutputStream();
            stdin.write(("echo __GXR_BEGIN__; " + command + "; echo __GXR_END__$?\n").getBytes(StandardCharsets.UTF_8));
            stdin.flush();
            String output = readUntil(process, "__GXR_END__", timeoutMs);
            int begin = output.indexOf("__GXR_BEGIN__");
            int end = output.lastIndexOf("__GXR_END__");
            if (begin < 0 || end < 0) throw new IOException("shell marker missing");
            String body = output.substring(begin + "__GXR_BEGIN__".length(), end);
            return body.replace("\r", "").trim();
        } finally {
            process.destroy();
            shellProcess = null;
        }
    }

    private static String readUntil(Process process, String marker, long timeoutMs) throws IOException, InterruptedException {
        StringBuilder out = new StringBuilder();
        InputStream stdout = process.getInputStream();
        byte[] buffer = new byte[4096];
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            int n;
            boolean progressed = false;
            while (stdout.available() > 0 && (n = stdout.read(buffer)) > 0) {
                out.append(new String(buffer, 0, n, StandardCharsets.UTF_8));
                progressed = true;
            }
            if (out.toString().contains(marker)) return out.toString();
            if (!progressed) Thread.sleep(100);
        }
        throw new IOException("shell read timeout");
    }

    /** One supervised attempt. Returns the run report. */
    public void runRoot(Log log) {
        runRoot(log, null);
    }

    /** One supervised attempt; onDone runs on this worker when the flow ends. */
    public void runRoot(Log log, Runnable onDone) {
        try {
            worker.execute(() -> {
                try {
                    java.io.PrintWriter writer = null;
                    try {
                        File logsDir = context.getExternalFilesDir("runs");
                        if (logsDir != null && (logsDir.isDirectory() || logsDir.mkdirs())) {
                            File runLog = new File(logsDir, "run-" + System.currentTimeMillis() + ".txt");
                            writer = new java.io.PrintWriter(new java.io.OutputStreamWriter(
                                new java.io.FileOutputStream(runLog, true), StandardCharsets.UTF_8), true);
                            writer.println("# run " + new java.util.Date().toString() + " fingerprint=" + Build.FINGERPRINT);
                        }
                    } catch (Exception ignored) {
                    }
                    final java.io.PrintWriter fileWriter = writer;
                    runLogWriter = writer;
                    Log tee = text -> {
                        log.line(text);
                        if (fileWriter != null) fileWriter.println(text);
                    };
                    try {
                        runRootInternal(tee);
                    } catch (Exception failure) {
                        tee.line("[!] failed: " + failure.getClass().getSimpleName() + ": " + failure.getMessage());
                    } finally {
                        if (fileWriter != null) fileWriter.close();
                        runLogWriter = null;
                    }
                } finally {
                    if (onDone != null) onDone.run();
                }
            });
        } catch (Exception rejected) {
            if (onDone != null) onDone.run();
        }
    }

    private void runRootInternal(Log log) throws Exception {
        cancelled = false;

        log.line("[*] starting local adb server");
        String server = startServer();
        if (!server.isEmpty()) log.line("    " + server.replace("\n", " "));
        pairIfNeeded(log);

        log.line("[*] discovering wireless debugging port (mDNS)");
        if (PortDiscovery.wirelessEnabled(context)) {
            log.line("    wireless debugging toggle: ON");
        } else {
            log.line("[!] wireless debugging toggle appears OFF (Settings > Developer options > Wireless debugging)");
        }
        List<Integer> candidates = PortDiscovery.discoverPorts(context, 10000, text -> log.line(text));
        String saved = prefs.getString("connect_port", "");
        if (!saved.isEmpty() && !candidates.contains(Integer.parseInt(saved))) {
            candidates.add(Integer.parseInt(saved));
            log.line("    saved port added: " + saved);
        }
        if (candidates.isEmpty()) throw new IOException("wireless debugging not reachable; turn the toggle ON, or save a manual port");

        /* Try each candidate. A wrong/stale port refuses instantly; the live
         * port either connects (already trusted) or shows offline/unauthorized
         * while the on-screen Allow dialog is pending. */
        int port = -1;
        String connectOut = "";
        long pendingSince = 0;
        for (int candidate : candidates) {
            log.line("[*] connecting to local wireless debugging (localhost:" + candidate + ")");
            connectOut = adbOnce(List.of("connect", "localhost:" + candidate), 60000);
            log.line("    " + connectOut.replace("\n", " "));
            if (connectOut.contains("connected to") || connectOut.contains("already connected")) {
                port = candidate;
                break;
            }
            // Offline/unauthorized means the port is live but approval is
            // pending on the headset screen. Keep this candidate.
            String state = adbOnce(List.of("devices"), 8000);
            if (state.contains("offline") || state.contains("unauthorized")) {
                port = candidate;
                pendingSince = System.currentTimeMillis();
                log.line("    live port with pending approval; watch the headset screen");
                break;
            }
        }
        if (port < 0) {
            pairIfNeeded(log);
            List<Integer> retry = PortDiscovery.discoverPorts(context, 10000, text2 -> log.line(text2));
            for (int candidate : retry) {
                String out = connect("localhost", candidate);
                log.line("    " + out.replace("\n", " "));
                if (out.contains("connected to") || out.contains("already connected")) { port = candidate; break; }
            }
        }
        if (port < 0) throw new IOException("local adb connect failed on all candidates: " + connectOut.trim());
        pendingSince = System.currentTimeMillis();
        adbSerial = "localhost:" + port;

        log.line("[*] waiting for the connection to come online");
        log.line("    if a dialog appears on the headset screen, tap Always allow");
        boolean online = false;
        long stateDeadline = System.currentTimeMillis() + 90000;
        boolean reconnectTried = false;
        while (System.currentTimeMillis() < stateDeadline) {
            String devices = adbOnce(List.of("devices"), 8000);
            if (devices.contains("\tdevice")) { online = true; break; }
            if (devices.contains("unauthorized")) {
                log.line("    waiting for you to tap Allow on the headset screen…");
            } else if (devices.contains("offline")) {
                log.line("    connection pending; tap Allow on the headset screen if shown…");
            }
            boolean stuck = devices.contains("unauthorized") || devices.contains("offline");
            if (stuck && !reconnectTried && System.currentTimeMillis() - pendingSince > 20000) {
                long recoveryStart = System.currentTimeMillis();
                log.line("[*] stale offline track: disconnecting localhost:" + port + " and re-discovering the port");
                try { adbOnce(List.of("disconnect", "localhost:" + port), 8000); } catch (Exception ignored) {}
                String sameOut = adbOnce(List.of("connect", "localhost:" + port), 20000);
                boolean sameLive = sameOut.contains("connected to") || sameOut.contains("already connected");
                if (!sameLive) {
                    List<Integer> again = PortDiscovery.discoverPorts(context, 10000, text -> log.line(text));
                    for (int candidate : again) {
                        String out = adbOnce(List.of("connect", "localhost:" + candidate), 20000);
                        if (out.contains("connected to") || out.contains("already connected")) { port = candidate; break; }
                    }
                }
                reconnectTried = true;
                pendingSince = System.currentTimeMillis();
                stateDeadline += System.currentTimeMillis() - recoveryStart;
            }
            try { Thread.sleep(3000); }
            catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); break; }
        }
        if (!online) {
            log.line("[!] connection did not come online");
            log.line("    check the headset screen for an Allow wireless debugging dialog,");
            log.line("    then press Root now again");
            throw new IOException("wireless connection not authorized in time");
        }
        prefs.edit().putString("connect_port", String.valueOf(port)).commit();

        String fingerprint = shellCommand("getprop ro.build.fingerprint", 10000);
        log.line("[*] live fingerprint: " + fingerprint);
        List<String> problems = identityProblems(fingerprint);
        if (!problems.isEmpty()) {
            for (String problem : problems) log.line("[!] " + problem);
            throw new IOException("target gate failed");
        }

        String bootId = bootId();
        log.line("[*] boot " + bootId);

        String attemptedBoot = prefs.getString("attempt_boot", "");
        if (attemptedBoot.equals(bootId)) {
            throw new IOException("an attempt was already made in this boot; reboot before trying again");
        }
        boolean attemptedEver = prefs.getBoolean("attempt_ever", false);
        String lastOutcome = prefs.getString("last_outcome", "");
        if (attemptedEver && !"rooted".equals(lastOutcome)) {
            throw new IOException("previous attempt did not verify as rooted; manual rearm required");
        }

        // Latch BEFORE launch (atomic in prefs, single writer thread).
        prefs.edit().putString("attempt_boot", bootId).putBoolean("attempt_ever", true).commit();
        log.line("[*] attempt latched for this boot");

        log.line("[*] pushing payload");
        File exploit = payloadFile(PAYLOAD_EXPLOIT);
        File daemon = payloadFile(PAYLOAD_DAEMON);
        File ksuModule = payloadFile(PAYLOAD_KSU);
        String externalPayloadDir = context.getExternalFilesDir("payload").getAbsolutePath();
        String push = shellCommand(
            "mkdir -p " + REMOTE_DIR + " && cp " + externalPayloadDir + "/" + PAYLOAD_EXPLOIT
                + " " + REMOTE_DIR + "/" + PAYLOAD_EXPLOIT
                + " && cp " + externalPayloadDir + "/" + PAYLOAD_DAEMON
                + " " + REMOTE_DIR + "/" + PAYLOAD_DAEMON
                + " && cp " + externalPayloadDir + "/" + PAYLOAD_KSU
                + " " + REMOTE_DIR + "/" + PAYLOAD_KSU
                + " && chmod 755 " + REMOTE_DIR + "/" + PAYLOAD_EXPLOIT
                + " " + REMOTE_DIR + "/" + PAYLOAD_DAEMON
                + " && echo PUSHED",
            30000);
        if (!push.contains("PUSHED")) throw new IOException("payload stage failed: " + push);
        log.line("    payload staged in " + REMOTE_DIR);

        log.line("[*] launching exploit (1 attempt, this may take a minute)");
        Process runProcess = openShell();
        long deadline = System.currentTimeMillis() + RUN_DEADLINE_MS;
        try {
            OutputStream stdin = runProcess.getOutputStream();
            stdin.write(("EXPLOIT_ATTEMPTS=1 EXPLOIT_ATTEMPTS_TIMEOUT_SEC=600 "
                + "LD_PRELOAD=" + REMOTE_DIR + "/" + PAYLOAD_EXPLOIT + " /system/bin/true; echo __GXR_RUN_DONE__$?\n")
                .getBytes(StandardCharsets.UTF_8));
            stdin.flush();
            InputStream stdout = runProcess.getInputStream();
            byte[] buffer = new byte[4096];
            StringBuilder runOut = new StringBuilder();
            while (System.currentTimeMillis() < deadline) {
                int n;
                boolean progressed = false;
                while (stdout.available() > 0 && (n = stdout.read(buffer)) > 0) {
                    String chunk = new String(buffer, 0, n, StandardCharsets.UTF_8);
                    runOut.append(chunk);
                    for (String line : chunk.split("\n")) {
                        String trimmed = line.trim();
                        if (!trimmed.isEmpty()) log.line("    " + trimmed);
                    }
                    progressed = true;
                }
                if (runOut.toString().contains("__GXR_RUN_DONE__")) break;
                if (!progressed) Thread.sleep(200);
            }
            if (!runOut.toString().contains("__GXR_RUN_DONE__")) {
                log.line("[!] exploit did not finish in time; NOT killing it. Reboot the headset if it hangs.");
                prefs.edit().putString("last_outcome", "timeout").commit();
                return;
            }
        } finally {
            // Closing stdin/session only; the remote command already finished.
            runProcess.destroy();
            shellProcess = null;
        }

        log.line("[*] verifying root through the daemon");
        String id = shellCommand(REMOTE_DIR + "/" + PAYLOAD_DAEMON + " -c id", 20000);
        log.line("    " + id.replace("\n", " "));
        boolean rooted = id.contains("uid=0(root)");
        prefs.edit().putString("last_outcome", rooted ? "rooted" : "not_rooted").commit();
        if (rooted) {
            log.line("[+] ROOT VERIFIED");
            String selinux = shellCommand(REMOTE_DIR + "/" + PAYLOAD_DAEMON + " -c getenforce", 20000);
            log.line("    SELinux: " + selinux.replace("\n", " "));
            loadKernelSu(log);
        } else {
            log.line("[!] root not verified; no retry this boot");
        }
    }

    /**
     * Late-loads the KernelSU module through the ghost daemon. Deliberately last: after
     * the driver is in it owns root and SELinux returns to enforcing, so the daemon stops
     * being the root provider. Repeatable; an already-loaded module reports "File exists".
     */
    private void loadKernelSu(Log log) {
        log.line("[*] late-loading KernelSU");
        try {
            String load = shellCommand(
                REMOTE_DIR + "/" + PAYLOAD_DAEMON + " -c \"insmod " + REMOTE_DIR + "/" + PAYLOAD_KSU
                    + " allow_shell=1\"",
                30000).trim();
            if (!load.isEmpty() && !load.contains("File exists")) {
                log.line("    " + load.replace("\n", " "));
            }
        } catch (Exception e) {
            log.line("[!] KernelSU load failed: " + e.getMessage());
            return;
        }
        try {
            String loaded = shellCommand("grep -c kernelsu /proc/modules", 20000).trim();
            if (loaded.isEmpty() || loaded.endsWith("0")) {
                log.line("[!] KernelSU not loaded; root stays with the ghost daemon this boot");
                return;
            }
            prefs.edit().putBoolean("ksu_loaded", true).commit();
            log.line("[+] KernelSU loaded: su for allowed apps and for shell (allow_shell=1)");
        } catch (Exception e) {
            log.line("[!] KernelSU check failed: " + e.getMessage());
        }
    }

    public void setConnectPort(String port) {
        prefs.edit().putString("connect_port", port).commit();
    }

    public String pairCode() {
        return prefs.getString("pair_code", "");
    }

    public void setPairCode(String code) {
        prefs.edit().putString("pair_code", code).commit();
    }

    public int pairPort() {
        return prefs.getInt("pair_port", -1);
    }

    public void setPairPort(int port) {
        prefs.edit().putInt("pair_port", port).commit();
    }

    /** Pairs with the code from Developer options; needs the pairing dialog open. */
    private boolean pairIfNeeded(Log log) {
        String code = pairCode();
        if (code.isEmpty()) {
            log.line("[!] pairing needs the code from Developer options > Wireless debugging");
            return false;
        }
        int pairingPort = pairPort();
        if (pairingPort <= 0) {
            List<Integer> found = PortDiscovery.discoverPairingPorts(context, 10000, text -> log.line(text));
            if (!found.isEmpty()) {
                pairingPort = found.get(0);
                setPairPort(pairingPort);
            }
        }
        if (pairingPort <= 0) {
            log.line("[!] no pairing port found; open the Pair device with correct pairing code dialog on the headset");
            return false;
        }
        try {
            String out = pair("localhost", pairingPort, code);
            String lower = out.toLowerCase();
            boolean paired = lower.contains("successfully paired") || lower.contains("already paired");
            if (paired) {
                log.line("    paired on port " + pairingPort);
                return true;
            }
            setPairPort(-1);
            log.line("[*] pairing not available on port " + pairingPort
                    + "; open the pairing dialog on the headset to pair a new key");
            return false;
        } catch (Exception failure) {
            setPairPort(-1);
            log.line("[*] pairing skipped: " + failure.getClass().getSimpleName()
                    + (failure.getMessage() == null ? "" : ": " + failure.getMessage()));
            return false;
        }
    }

    public void rearm() {
        prefs.edit().putBoolean("attempt_ever", false).putString("last_outcome", "").putString("attempt_boot", "").commit();
    }

    /** Synchronous root check via the daemon; never claims the device is unrooted. */
    public JSONObject verifyRoot() {
        JSONObject out = new JSONObject();
        try {
            if (adbSerial == null || adbSerial.isEmpty()) {
                String connected = "";
                try {
                    startServer();
                    List<Integer> candidates = PortDiscovery.discoverPorts(context, 10000, text -> {});
                    String saved = prefs.getString("connect_port", "");
                    if (!saved.isEmpty() && !candidates.contains(Integer.parseInt(saved))) {
                        candidates.add(Integer.parseInt(saved));
                    }
                    for (int candidate : candidates) {
                        connected = adbOnce(List.of("connect", "localhost:" + candidate), 60000);
                        if (connected.contains("connected to") || connected.contains("already connected")) {
                            adbSerial = "localhost:" + candidate;
                            break;
                        }
                    }
                } catch (Exception ignored) {
                }
                if (adbSerial == null || adbSerial.isEmpty()) {
                    out.put("state", "unreachable");
                    out.put("reason", "Not connected to the headset, so root cannot be checked right now.");
                    out.put("output", connected);
                    return out;
                }
            }
            /* KernelSU first: once the boot flow loads the module it owns root and the ghost
             * daemon stops answering, so the daemon path alone would report root as lost. */
            JSONObject kernelSu = verifyRootViaKernelSu();
            if ("verified_root".equals(kernelSu.optString("state"))) return kernelSu;
            String failure = null;
            String text;
            try {
                text = shellCommand(REMOTE_DIR + "/" + PAYLOAD_DAEMON + " -c id", 20000);
            } catch (Exception exception) {
                text = exception.getClass().getSimpleName() + ": " + exception.getMessage();
                failure = text;
            }
            if (failure != null) {
                /* The pinned transport may be stale; re-discover once before giving up. */
                adbSerial = null;
                try {
                    startServer();
                    for (int candidate : PortDiscovery.discoverPorts(context, 10000, ignored -> {})) {
                        String connected = adbOnce(List.of("connect", "localhost:" + candidate), 20000);
                        if (connected.contains("connected to") || connected.contains("already connected")) {
                            adbSerial = "localhost:" + candidate;
                            break;
                        }
                    }
                } catch (Exception ignored) {
                }
                if (adbSerial != null && !adbSerial.isEmpty()) {
                    failure = null;
                    try {
                        text = shellCommand(REMOTE_DIR + "/" + PAYLOAD_DAEMON + " -c id", 20000);
                    } catch (Exception exception) {
                        text = exception.getClass().getSimpleName() + ": " + exception.getMessage();
                        failure = text;
                    }
                }
            }
            String state;
            String reason;
            if (text.contains("uid=0(root)")) {
                state = "verified_root";
                reason = "Root is active for this boot.";
            } else if (failure != null) {
                state = "unreachable";
                reason = "Root could not be checked: " + failure;
            } else if (text.trim().isEmpty() || text.contains("not found") || text.contains("No such file")) {
                state = "unreachable";
                reason = "The root server did not answer in this boot.";
            } else if (text.contains("permission denied")) {
                state = "not_authorized";
                reason = "The root check was refused in this session; the daemon allows only the UID that started it.";
            } else {
                state = "not_rooted";
                reason = "The root daemon answered but did not report uid=0.";
            }
            if ("verified_root".equals(state)) {
                out.put("state", state);
                out.put("reason", reason);
                out.put("channel", "daemon");
                out.put("ksu_loaded", false);
                out.put("output", text);
                return out;
            }
            String ksuState = kernelSu.optString("state");
            if ("ksu_denied".equals(ksuState) || "ksu_missing".equals(ksuState)) {
                /* The module's own verdict is the actionable one. */
                out.put("state", ksuState);
                out.put("reason", kernelSu.optString("reason"));
                out.put("channel", "kernelsu");
                out.put("ksu_loaded", false);
                out.put("output", kernelSu.optString("output") + (text.trim().isEmpty() ? "" : " | " + text));
                return out;
            }
            out.put("state", state);
            out.put("reason", reason);
            out.put("channel", "daemon");
            out.put("ksu_loaded", false);
            out.put("output", text);
        } catch (Exception failure) {
            try {
                out.put("state", "unreachable");
                out.put("reason", "Root could not be checked: " + failure.getClass().getSimpleName() + ": " + failure.getMessage());
                out.put("output", "");
            } catch (Exception ignored) {
            }
        }
        return out;
    }

    /**
     * KernelSU-backed root proof, used once the module owns root. Deliberately strict: the
     * driver must be live, `su` must report uid 0, and its boot id must match the kernel's
     * own, so a stale or unrelated answer cannot pass as root.
     */
    private JSONObject verifyRootViaKernelSu() {
        JSONObject out = new JSONObject();
        String output = "";
        try {
            String module = shellCommand("grep -c kernelsu /proc/modules", 20000).trim();
            if (module.isEmpty() || module.endsWith("0")) {
                out.put("state", "ksu_missing");
                out.put("reason", "KernelSU is not loaded in this boot. It is required for root here: "
                        + "reboot so this app loads it with the boot flow, or install the module again.");
                out.put("output", "kernelsu module count: " + module);
                return out;
            }
            String bootId = shellCommand("cat /proc/sys/kernel/random/boot_id", 20000).trim();
            String su;
            try {
                su = shellCommand("su -c \"id; cat /proc/sys/kernel/random/boot_id\"", 20000).trim();
            } catch (Exception refusal) {
                su = refusal.getClass().getSimpleName() + ": " + refusal.getMessage();
            }
            output = "KernelSU loaded; su said: " + su;
            if (!su.contains("uid=0(root)")) {
                out.put("state", "ksu_denied");
                out.put("reason", "KernelSU is loaded but su was refused: " + su
                        + " Grant this app or shell in the KernelSU manager, or let the boot flow "
                        + "load the module with allow_shell=1.");
                out.put("output", output);
                return out;
            }
            if (bootId.isEmpty() || !su.contains(bootId)) {
                out.put("state", "ksu_stale");
                out.put("reason", "KernelSU answered for a different boot; check again.");
                out.put("output", output);
                return out;
            }
            out.put("state", "verified_root");
            out.put("reason", "Root is active for this boot through KernelSU: uid 0 in the ksu domain.");
            out.put("channel", "kernelsu");
            out.put("ksu_loaded", true);
            out.put("output", output);
            return out;
        } catch (Exception failure) {
            try {
                out.put("state", "unreachable");
                out.put("reason", "The KernelSU check could not run: " + failure.getClass().getSimpleName()
                        + (failure.getMessage() == null ? "" : ": " + failure.getMessage()));
                out.put("output", output);
            } catch (Exception ignored) {
            }
            return out;
        }
    }

    public JSONObject status() {
        JSONObject out = new JSONObject();
        try {
            out.put("connect_port", prefs.getString("connect_port", ""));
            out.put("attempt_boot", prefs.getString("attempt_boot", ""));
            out.put("attempt_ever", prefs.getBoolean("attempt_ever", false));
            out.put("last_outcome", prefs.getString("last_outcome", ""));
            out.put("model", Build.MODEL);
            out.put("fingerprint", Build.FINGERPRINT);
            out.put("payload_exploit_ok", new File(context.getFilesDir(), "payload/" + PAYLOAD_EXPLOIT).isFile());
            out.put("payload_daemon_ok", new File(context.getFilesDir(), "payload/" + PAYLOAD_DAEMON).isFile());
            out.put("untested", new JSONArray(new String[]{"OTA/snapshot state", "allocation keeper lifetime"}));
        } catch (Exception ignored) {
        }
        return out;
    }
}