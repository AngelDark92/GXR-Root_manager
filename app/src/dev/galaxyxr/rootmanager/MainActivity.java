package dev.galaxyxr.rootmanager;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.text.InputType;
import android.text.Spannable;
import android.text.SpannableStringBuilder;
import android.text.style.ForegroundColorSpan;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewTreeObserver;
import android.view.Window;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import org.json.JSONObject;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

/**
 * One screen: root status, the two actions that matter, a log, and the rare fallbacks.
 * Root is kernel-memory only, so it is re-obtained once per boot, optionally by RootService.
 */
public final class MainActivity extends Activity {
    private static final int BACKGROUND = Color.rgb(13, 20, 29);
    private static final int CARD = Color.rgb(24, 35, 47);
    private static final int INK = Color.rgb(235, 243, 249);
    private static final int MUTED = Color.rgb(167, 185, 198);
    private static final int ACCENT = Color.rgb(109, 228, 193);
    private static final int WARN = Color.rgb(240, 173, 78);
    private static final int LOG_LIMIT = 300;
    /**
     * KernelSU-Next manager. Root here is kernel-memory only, so its manager is what keeps `su`
     * usable after every restart; this app refuses to root until the manager app is installed.
     * Keep this package in the AndroidManifest.xml <queries> block, or the check below fails
     * on API 30+ even when the manager is installed.
     */
    private static final String KSU_MANAGER_PACKAGE = "com.rifsxd.ksunext";
    /**
     * Stable alias asset that every KernelSU-Next-GXR release publishes. The versioned APK name
     * changes whenever upstream does; this one never does, so the link keeps resolving to the
     * newest manager without this app ever being rebuilt.
     */
    private static final String KSU_MANAGER_APK_URL =
            "https://github.com/AngelDark92/KernelSU-Next-GXR/releases/latest/download/"
                    + "KernelSU-Next-manager.apk";

    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private RootEngine engine;
    private LinearLayout page;
    private LinearLayout logCard;
    private ScrollView pageScroll;
    private ScrollView logScroll;
    private TextView logTextView;
    private final List<String> logBuffer = new java.util.ArrayList<>();
    private boolean logFollowArmed;
    /**
     * Fires once after the new log text has been laid out, so the scroll below can never run
     * against a stale measured height. Not a focus op: the page around the log stays put.
     */
    private final ViewTreeObserver.OnGlobalLayoutListener logFollowListener =
            new ViewTreeObserver.OnGlobalLayoutListener() {
                @Override
                public void onGlobalLayout() {
                    logFollowArmed = false;
                    if (logTextView != null) {
                        logTextView.getViewTreeObserver().removeOnGlobalLayoutListener(this);
                    }
                    if (logScroll != null) {
                        // ScrollView clamps the overshoot to the exact bottom.
                        logScroll.scrollTo(0, Integer.MAX_VALUE);
                    }
                }
            };
    private TextView statusView;
    private TextView statusDetail;
    private TextView ksuView;
    private Button rootButton;
    private Button verifyButton;
    private Button removeButton;
    private CheckBox autoBootBox;
    private boolean busy;
    private boolean pendingRootOutcome;
    private boolean pairing;
    private boolean autoBootAccepted;
    private boolean autoBootRevert;
    private static boolean autoChecked;
    private final List<Button> gatedButtons = new java.util.ArrayList<>();

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        Window window = getWindow();
        window.setBackgroundDrawable(new ColorDrawable(BACKGROUND));
        if (Build.VERSION.SDK_INT >= 34) window.setHideOverlayWindows(true);
        engine = new RootEngine(this);
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission("android.permission.POST_NOTIFICATIONS")
                != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, 1);
        }
        showPage();
        if (!ksuManagerInstalled()) {
            appendLog("[!] root locked: KernelSU-Next is not installed");
            showKernelSuRequired();
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        showStoredStatus();
        applyRemovalGates();
        if (!autoChecked && !busy) {
            autoChecked = true;
            verify();
        }
    }

    @Override
    protected void onDestroy() {
        if (engine != null) engine.shutdown();
        worker.shutdown();
        super.onDestroy();
    }

    // ---------- actions ----------

    private void startRoot() {
        if (busy) return;
        if (rootRemovedThisBoot()) {
            appendLog("[!] root was removed this boot; restart to continue");
            danger("Root was removed this boot",
                    "The kernel still holds this boot's root until a restart, and the removal finishes "
                            + "there. Restart the headset, then root again.",
                    "Got it", null);
            return;
        }
        if (!ksuManagerInstalled()) {
            appendLog("[!] root locked: KernelSU-Next is not installed");
            showKernelSuRequired();
            return;
        }
        JSONObject latch = engine.status();
        if (latch.optBoolean("attempt_ever") && !"rooted".equals(latch.optString("last_outcome"))) {
            appendLog("[!] previous attempt did not verify root; rearm required");
            danger("Previous attempt did not verify root",
                    "The last attempt did not confirm root, so the app holds a latch that stops silent "
                            + "retries.\n\nClear it and try again now? Root is still per-boot and nothing "
                            + "was flashed.\nIf the headset seems unstable, restart it instead.",
                    "Rearm and continue",
                    () -> {
                        engine.rearm();
                        appendLog("[*] rearm requested");
                        showStoredStatus();
                        startRoot();
                    });
            return;
        }
        if (engine.pairCode().isEmpty()) {
            appendLog("[!] pairing code missing");
            danger("Pairing code required",
                    "Pairing is required on this build. On the headset open Settings > General > "
                            + "Developer options > Wireless debugging > Pair device with pairing code, "
                            + "then type the 6-digit code shown there into the Pairing card below and "
                            + "press Pair now.",
                    "Open Developer options", this::openDeveloperOptions);
            return;
        }
        beginRootRun();
    }

    /** Starts the supervised run. Only called after every preflight gate has passed. */
    private void beginRootRun() {
        setBusy(true);
        appendLog("[*] supervised root attempt for this boot");
        scrollToLog();
        pendingRootOutcome = true;
        engine.runRoot(line -> appendLog(line), () -> runOnUiThread(this::verify));
    }

    private void findPairingPort(EditText pairPort) {
        appendLog("[*] scanning for the pairing port");
        worker.execute(() -> {
            List<Integer> ports = PortDiscovery.discoverPairingPorts(this, 10000, this::appendLog);
            runOnUiThread(() -> {
                if (isDestroyed()) return;
                if (ports.isEmpty()) {
                    appendLog("[!] no pairing port advertised; is the pairing dialog open?");
                    danger("Pairing port not found",
                            "No pairing port was advertised. Open Settings > General > Developer "
                                    + "options > Wireless debugging > Pair device with pairing code and "
                                    + "keep that dialog open, then press Find port again. The pairing "
                                    + "port is not the connect port.",
                            "Open settings", this::openDeveloperOptions);
                    return;
                }
                int port = ports.get(0);
                engine.setPairPort(port);
                pairPort.setText(String.valueOf(port));
                appendLog("[*] pairing port " + port);
            });
        });
    }

    private void savePairing(EditText pairCode, EditText pairPort) {
        String code = pairCode.getText().toString().trim();
        String port = pairPort.getText().toString().trim();
        engine.setPairCode(code);
        if (!port.isEmpty()) {
            try {
                engine.setPairPort(Integer.parseInt(port));
            } catch (NumberFormatException ignored) {
            }
        }
        appendLog(code.isEmpty() ? "[!] pairing code cleared" : "[*] pairing code saved");
    }

    private void pairNow(EditText pairCode, EditText pairPort) {
        if (pairing) return;
        pairing = true;
        savePairing(pairCode, pairPort);
        String code = engine.pairCode();
        if (code.isEmpty()) {
            appendLog("[!] enter the pairing code first");
            danger("Pairing code missing",
                    "Type the 6-digit code from the headset's Pair device with pairing code dialog into "
                            + "the Pairing card, then press Pair now.",
                    "Got it", null);
            pairing = false;
            return;
        }
        appendLog("[*] pairing");
        scrollToLog();
        worker.execute(() -> {
            try {
                int port = engine.pairPort();
                if (port <= 0) {
                    List<Integer> ports = PortDiscovery.discoverPairingPorts(this, 10000, this::appendLog);
                    if (ports.isEmpty()) {
                        appendLog("[!] no pairing port advertised; is the pairing dialog open?");
                        runOnUiThread(() -> {
                            if (isDestroyed()) return;
                            pairing = false;
                            danger("Pairing port not found",
                                    "No pairing port was advertised. Open Settings > General > "
                                            + "Developer options > Wireless debugging > Pair device "
                                            + "with pairing code and keep that dialog open, then "
                                            + "press Find port again. The pairing port is not the "
                                            + "connect port.",
                                    "Open settings", this::openDeveloperOptions);
                        });
                        return;
                    }
                    port = ports.get(0);
                    engine.setPairPort(port);
                    int found = port;
                    runOnUiThread(() -> pairPort.setText(String.valueOf(found)));
                }
                String output = engine.pair("localhost", port, code);
                appendLog("    " + output.replace("\n", " "));
                String lower = output.toLowerCase();
                boolean paired = lower.contains("successfully paired") || lower.contains("already paired");
                int pairedPort = port;
                String report = output.replace("\n", " ").trim();
                runOnUiThread(() -> {
                    if (isDestroyed()) return;
                    pairing = false;
                    if (paired) {
                        danger("Pairing succeeded",
                                "Paired with the headset on port " + pairedPort + ". You can press Root now.",
                                "Got it", null);
                    } else {
                        danger("Pairing failed",
                                "The headset refused pairing on port " + pairedPort + ": " + report
                                        + "\nA wrong code or a stale port is the usual cause. Re-open "
                                        + "Pair device with pairing code, press Find port, then Pair now.",
                                "Got it", null);
                    }
                });
            } catch (Exception failure) {
                appendLog("[!] pair failed: " + failure.getMessage());
                String message = failure.getMessage() == null ? failure.toString() : failure.getMessage();
                runOnUiThread(() -> {
                    if (isDestroyed()) return;
                    pairing = false;
                    danger("Pairing failed",
                            "Pairing could not run: " + message + "\nOpen Settings > General > "
                                    + "Developer options > Wireless debugging > Pair device with "
                                    + "pairing code, then press Find port and Pair now.",
                            "Got it", null);
                });
            }
        });
    }

    private void verify() {
        setBusy(true);
        applyResult(null);
        worker.execute(() -> {
            JSONObject result = null;
            String output = "";
            try {
                result = engine.verifyRoot();
                output = result.optString("output");
            } catch (Throwable failure) {
                output = "";
            }
            JSONObject finalResult = result;
            String finalOutput = output;
            runOnUiThread(() -> {
                if (isDestroyed()) return;
                showStoredStatus();
                applyResult(finalResult);
                if (!finalOutput.isEmpty()) appendLog(finalOutput.replace("\n", " "));
                setBusy(false);
                if (pendingRootOutcome) {
                    pendingRootOutcome = false;
                    showRootOutcome(finalResult);
                }
            });
        });
    }

    /** The end-of-run verdict dialog; only shown for a supervised run, never for Verify root alone. */
    private void showRootOutcome(JSONObject result) {
        String state = result == null ? "" : result.optString("state");
        String reason = result == null ? "" : result.optString("reason");
        if ("verified_root".equals(state)) {
            boolean ksuLoaded = result != null && result.optBoolean("ksu_loaded");
            danger("Root succeeded",
                    "Root is active for this boot" + (ksuLoaded ? " through KernelSU." : " through the ghost daemon.")
                            + "\nThe attempt latch stays spent until you restart or rearm.\nNothing was flashed.",
                    "Got it", null);
            return;
        }
        if ("timeout".equals(engine.status().optString("last_outcome"))) {
            danger("Root run did not finish",
                    "The exploit did not finish within the deadline. It was not killed. If the headset "
                            + "hangs, hold power to restart it.\nRoot is not verified yet — press Verify "
                            + "root, or restart for a fresh attempt.",
                    "Got it", null);
            return;
        }
        String lower = reason.toLowerCase();
        boolean offerSettings = "unreachable".equals(state)
                || lower.contains("wireless") || lower.contains("connect");
        danger("Root not verified",
                (reason.isEmpty() ? "The run did not confirm root." : reason)
                        + "\n\nCheck the log for the failing step.\n"
                        + "- Wireless debugging must be on: Settings > General > Developer options > "
                        + "Wireless debugging. The pairing code and ports live in the Pairing card "
                        + "(a wrong saved port is a common cause — fix via Find port or the Advanced "
                        + "card).\n"
                        + "- An unavailable check never means the device has no root.\n"
                        + "After fixing, press Rearm or restart for a fresh attempt — one attempt per boot.",
                offerSettings ? "Open Developer options" : "Got it",
                offerSettings ? this::openDeveloperOptions : null);
    }

    private void applyResult(JSONObject result) {
        String state = result == null ? "" : result.optString("state");
        String reason = result == null ? "" : result.optString("reason");
        boolean ksuLoaded = result != null && result.optBoolean("ksu_loaded");
        String channel = result == null ? "" : result.optString("channel");
        String label;
        int color;
        if ("verified_root".equals(state)) {
            label = "kernelsu".equals(channel)
                    ? "Root active for this boot (KernelSU)"
                    : "Root active for this boot";
            color = ACCENT;
        } else if ("ksu_missing".equals(state)) {
            label = "KernelSU not loaded — it is required here";
            color = WARN;
        } else if ("ksu_denied".equals(state)) {
            label = "KernelSU is loaded but refused su";
            color = WARN;
        } else if ("not_authorized".equals(state)) {
            label = "Root check refused for this session";
            color = WARN;
        } else if ("not_rooted".equals(state)) {
            label = "Root server answered without uid=0";
            color = WARN;
        } else if (reason.isEmpty()) {
            label = "Checking root…";
            color = MUTED;
        } else {
            label = "Root could not be verified";
            color = MUTED;
        }
        statusView.setText(label);
        statusView.setTextColor(color);
        if (!reason.isEmpty()) {
            statusDetail.setText(reason + "\nAn unavailable check does not mean the device has no root.");
        }
        if (ksuView != null) {
            ksuView.setText(ksuLoaded
                    ? "KernelSU: loaded. It grants root per app from its manager; the ghost daemon is "
                            + "no longer the root provider."
                    : "KernelSU: not loaded. Root in this build requires the module — the boot flow "
                            + "loads it, and the module page has it if that fails.");
        }
    }

    private boolean ksuManagerInstalled() {
        try {
            getPackageManager().getPackageInfo(KSU_MANAGER_PACKAGE, 0);
            return true;
        } catch (PackageManager.NameNotFoundException missing) {
            return false;
        }
    }

    private void showKernelSuRequired() {
        danger("KernelSU-Next is required",
                "Root on this headset only works with the KernelSU-Next manager installed. Root "
                        + "stays in kernel memory, and only the manager hands it back after a "
                        + "restart; this app ships the module, but nothing can use root without "
                        + "the manager.\n\n"
                        + "Install the manager APK first:\n"
                        + KSU_MANAGER_APK_URL + "\n\n"
                        + "Root now and Re-root after every restart stay locked until it is "
                        + "installed and detected.",
                "Download the APK", this::openKsuManagerDownload);
    }

    private void openKsuManagerDownload() {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(KSU_MANAGER_APK_URL)));
        } catch (Throwable failure) {
            appendLog("[!] no app can open " + KSU_MANAGER_APK_URL);
        }
    }

    private void openKernelSuPage() {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(RootEngine.KSU_MODULE_URL)));
        } catch (Throwable failure) {
            appendLog("[!] no app can open " + RootEngine.KSU_MODULE_URL);
        }
    }

    private void showStoredStatus() {
        JSONObject status = engine.status();
        String outcome = status.optString("last_outcome");
        String port = status.optString("connect_port");
        statusDetail.setText("Last attempt: " + (outcome.isEmpty() ? "none" : outcome)
                + " · rearm " + (status.optBoolean("attempt_ever") ? "needed after a failure" : "not needed")
                + (port.isEmpty() ? "" : " · port " + port)
                + " · boot re-root " + (RootService.autoBoot(this) ? "on" : "off")
                + "\nAn unavailable check does not mean the device has no root.");
    }

    private void setBusy(boolean value) {
        busy = value;
        if (rootButton != null) rootButton.setEnabled(!value);
        if (verifyButton != null) verifyButton.setEnabled(!value);
        for (Button button : gatedButtons) button.setEnabled(!value);
        applyRemovalGates();
    }

    /** After Remove root the rest of this boot must not offer rooting again. */
    private boolean rootRemovedThisBoot() {
        return engine.status().optBoolean("root_removed_this_boot");
    }

    private void applyRemovalGates() {
        boolean removed = rootRemovedThisBoot();
        if (rootButton != null) rootButton.setEnabled(!busy && !removed);
        if (removeButton != null) removeButton.setEnabled(!busy && !removed);
        if (autoBootBox != null) autoBootBox.setEnabled(!busy && !removed);
    }

    // ---------- page ----------

    private void showPage() {
        pageScroll = new ScrollView(this);
        pageScroll.setFillViewport(true);
        pageScroll.setBackgroundColor(BACKGROUND);
        page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(dp(24), dp(24), dp(24), dp(32));
        pageScroll.addView(page, new ScrollView.LayoutParams(-1, -2));
        setContentView(pageScroll);

        text(page, "GALAXY XR", 14, ACCENT, true);
        text(page, "Root Manager", 30, INK, true);
        text(page, versionName() + " · " + Build.MODEL, 14, MUTED, false);

        LinearLayout root = card("Root");
        statusView = text(root, "Checking root…", 20, INK, true);
        statusDetail = text(root, "", 14, MUTED, false);
        LinearLayout actions = new LinearLayout(this);
        actions.setOrientation(LinearLayout.HORIZONTAL);
        rootButton = button(actions, "Root now", true, ignored -> confirmRoot());
        verifyButton = button(actions, "Verify root", true, ignored -> verify());
        root.addView(actions, new LinearLayout.LayoutParams(-1, -2));
        ksuView = text(root, "", 14, MUTED, false);
        gatedButtons.add(button(root, "Get KernelSU-Next (app + module)", false, ignored -> openKernelSuPage()));

        CheckBox autoBoot = new CheckBox(this);
        autoBoot.setText("Re-root after every restart");
        autoBoot.setTextColor(INK);
        autoBoot.setTextSize(15);
        autoBootRevert = true;                     // consume the listener for the initial set
        autoBoot.setChecked(RootService.autoBoot(this));
        autoBootRevert = false;                    // setChecked fires synchronously; safe afterwards
        autoBootBox = autoBoot;
        autoBoot.setOnCheckedChangeListener((view, checked) -> {
            if (autoBootRevert) {
                autoBootRevert = false;
                return;
            }
            if (rootRemovedThisBoot()) {
                autoBootRevert = true;
                view.setChecked(false);
                return;
            }
            if (!checked) {
                autoBootAccepted = false;
                RootService.setAutoBoot(this, false);
                appendLog("[*] boot re-root disabled");
            } else if (!ksuManagerInstalled()) {
                autoBootRevert = true;
                view.setChecked(false);
                appendLog("[!] boot re-root locked: KernelSU-Next is not installed");
                showKernelSuRequired();
            } else if (autoBootAccepted) {
                autoBootAccepted = false;
                RootService.setAutoBoot(this, true);
                appendLog("[*] boot re-root enabled — applies from the next restart");
                danger("Boot re-root enabled",
                        "From the next restart the headset re-roots itself with no one watching the screen. "
                                + "This boot keeps the root it already has.",
                        "Got it", null);
            } else {
                autoBootRevert = true;
                view.setChecked(false);
                danger("Re-root after every restart?",
                        "Every restart would run the exploit again by itself, with no one watching the "
                                + "screen.\n\n"
                                + "- Each boot gets one automatic attempt; a failed attempt stays latched "
                                + "until you rearm.\n"
                                + "- A crash during an unattended run can leave the headset on a black "
                                + "screen until you restart it.\n"
                                + "- Unattended restarts also need the one-time WRITE_SECURE_SETTINGS grant "
                                + "shown below, and\n"
                                + "  Wireless debugging must be able to re-enable itself.\n"
                                + "- Root is still kernel-memory only and disappears on the next restart.\n"
                                + "- No warranty. You accept the risk by pressing the button below.",
                        "I accept \u2014 enable",
                        () -> {
                            RootService.setAutoBoot(this, true);          // the write IS the accept
                            autoBootAccepted = true;
                            view.setChecked(true);
                        },
                        true);
            }
        });
        root.addView(autoBoot, new LinearLayout.LayoutParams(-1, -2));

        if (checkSelfPermission("android.permission.WRITE_SECURE_SETTINGS")
                != PackageManager.PERMISSION_GRANTED) {
            text(root, "Unattended restarts need a one-time grant from a shell:\n"
                    + "pm grant dev.galaxyxr.rootmanager android.permission.WRITE_SECURE_SETTINGS",
                    13, WARN, false);
        }

        LinearLayout pairing = card("Pairing");
        text(pairing, "Pairing is required on this build. On the headset open Settings > General > "
                + "Developer options > Wireless debugging > Pair device with pairing code, keep that "
                + "dialog open, then use Find port and Pair now here.", 14, MUTED, false);
        EditText pairCode = new EditText(this);
        pairCode.setHint("Pairing code (6 digits)");
        pairCode.setHintTextColor(MUTED);
        pairCode.setTextColor(INK);
        pairCode.setInputType(InputType.TYPE_CLASS_NUMBER);
        pairCode.setText(engine.pairCode());
        pairing.addView(pairCode, new LinearLayout.LayoutParams(-1, -2));
        EditText pairPort = new EditText(this);
        pairPort.setHint("Pairing port (Find port fills this)");
        pairPort.setHintTextColor(MUTED);
        pairPort.setTextColor(INK);
        pairPort.setInputType(InputType.TYPE_CLASS_NUMBER);
        if (engine.pairPort() > 0) pairPort.setText(String.valueOf(engine.pairPort()));
        pairing.addView(pairPort, new LinearLayout.LayoutParams(-1, -2));
        LinearLayout pairActions = new LinearLayout(this);
        pairActions.setOrientation(LinearLayout.HORIZONTAL);
        gatedButtons.add(button(pairActions, "Find port", true, ignored -> findPairingPort(pairPort)));
        gatedButtons.add(button(pairActions, "Save code", true, ignored -> savePairing(pairCode, pairPort)));
        gatedButtons.add(button(pairActions, "Pair now", true, ignored -> pairNow(pairCode, pairPort)));
        pairing.addView(pairActions, new LinearLayout.LayoutParams(-1, -2));

        logCard = card("Log");
        logScroll = new ScrollView(this);
        logTextView = new TextView(this);
        logTextView.setTextSize(13);
        logTextView.setTextColor(MUTED);
        logTextView.setPadding(0, dp(4), 0, dp(8));
        /* Read-only box, deliberately NOT focusable and NOT selectable: on XR a selectable
         * TextView turns drags on it into text-selection gestures (the log then refuses to
         * scroll) and lets the focused child pull the page back to itself. Copy log covers
         * copying. */
        logTextView.setFocusable(false);
        logTextView.setFocusableInTouchMode(false);
        logTextView.setClickable(false);
        logTextView.setLongClickable(false);
        logTextView.setText("No run yet.");
        logScroll.addView(logTextView, new ScrollView.LayoutParams(-1, -2));
        logScroll.setFillViewport(true);
        logCard.addView(logScroll, new LinearLayout.LayoutParams(-1, dp(240)));
        button(logCard, "Copy log", true, ignored -> copyLog());

        LinearLayout advanced = card("Advanced");
        EditText manualPort = new EditText(this);
        manualPort.setHint("Connect port — only if discovery fails");
        manualPort.setHintTextColor(MUTED);
        manualPort.setTextColor(INK);
        manualPort.setInputType(InputType.TYPE_CLASS_NUMBER);
        manualPort.setText(engine.status().optString("connect_port"));
        advanced.addView(manualPort, new LinearLayout.LayoutParams(-1, -2));
        gatedButtons.add(button(advanced, "Save port", true, ignored -> {
            String port = manualPort.getText().toString().trim();
            engine.setConnectPort(port);
            appendLog(port.isEmpty() ? "[*] manual port cleared" : "[*] manual port saved: " + port);
            showStoredStatus();
        }));

        gatedButtons.add(button(advanced, "Rearm after a failed attempt", true, ignored -> {
            engine.rearm();
            appendLog("[*] rearm requested");
            showStoredStatus();
            danger("Re-armed",
                    "The failed attempt is cleared. Press Root now to try again. If this boot already spent "
                            + "its attempt and the headset seems unstable, restart it first.",
                    "Got it", null);
        }));

        LinearLayout removal = card("Remove");
        text(removal, "Removes this app's root traces: the staged files in /data/local/tmp, the daemon "
                + "socket, boot re-root and the wireless-debugging setting. Kernel root stays active "
                + "until the next restart — nothing can clear kernel memory.", 14, MUTED, false);
        removeButton = button(removal, "Remove root", true, ignored -> confirmRemoveRoot());
        gatedButtons.add(removeButton);

        showStoredStatus();
        applyRemovalGates();
    }

    private void confirmRoot() {
        if (!ksuManagerInstalled()) {
            appendLog("[!] root locked: KernelSU-Next is not installed");
            showKernelSuRequired();
            return;
        }
        danger("Root this headset?",
                "Rooting runs a kernel exploit on your own Galaxy XR. Before you continue:\n\n"
                        + "- One attempt per boot; a failed attempt stays latched until you rearm or "
                        + "restart.\n"
                        + "- The exploit sets SELinux to permissive and clears panic_on_oops for this "
                        + "boot only.\n"
                        + "- A kernel exploit can crash or hang the headset; if it hangs, hold power to "
                        + "restart it.\n"
                        + "- Root lives in kernel memory only: a restart clears it and nothing is made "
                        + "persistent.\n"
                        + "- Nothing is flashed, no partition is written, the bootloader stays locked.\n"
                        + "- No warranty. You accept the risk by pressing the button below.",
                "I accept \u2014 root now", this::startRoot);
    }

    private void confirmRemoveRoot() {
        danger("Remove root traces?",
                "- Disables re-root after every restart.\n"
                        + "- Deletes the staged payload files and the daemon socket.\n"
                        + "- Reverts the wireless-debugging setting this app wrote.\n"
                        + "- Does not kill running root processes and cannot clear kernel memory — "
                        + "restart to finish.\n"
                        + "- Nothing is flashed; no warranty. You accept the risk by pressing below.",
                "Remove root", () -> removeRootFlow(ignored -> { }));
    }

    /** Cleanup runs on the worker; its log lines already stream via appendLog, and the
     *  report comes back on the UI thread. */
    private void removeRootFlow(Consumer<JSONObject> onReport) {
        setBusy(true);
        worker.execute(() -> {
            JSONObject report = null;
            try {
                report = engine.removeRoot(this::appendLog);
            } catch (Throwable failure) {
                appendLog("[!] remove failed: " + failure);
            }
            JSONObject finalReport = report == null ? new JSONObject() : report;
            runOnUiThread(() -> {
                if (isDestroyed()) return;
                setBusy(false);
                if (autoBootBox != null) {
                    autoBootRevert = true;
                    autoBootBox.setChecked(false);
                }
                onReport.accept(finalReport);
            });
        });
    }

    // ---------- helpers ----------

    private void appendLog(String line) {
        if (line == null || line.trim().isEmpty()) return;
        runOnUiThread(() -> {
            if (logTextView == null) return;
            logBuffer.add(line);
            while (logBuffer.size() > LOG_LIMIT) logBuffer.remove(0);
            SpannableStringBuilder text = new SpannableStringBuilder();
            for (String entry : logBuffer) {
                int start = text.length();
                text.append(entry).append('\n');
                text.setSpan(new ForegroundColorSpan(entry.startsWith("[+]") ? ACCENT : MUTED),
                        start, start + entry.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            }
            /* Always glue the log to its newest line; the one-shot layout listener scrolls
             * after the new text is measured, so the box is never a line short. */
            if (!logFollowArmed) {
                logFollowArmed = true;
                logTextView.getViewTreeObserver().addOnGlobalLayoutListener(logFollowListener);
            }
            logTextView.setText(text);
        });
    }

    /** Copies the whole retained log (up to LOG_LIMIT lines) to the clipboard. */
    private void copyLog() {
        if (isDestroyed()) return;
        ClipboardManager clipboard = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        if (clipboard == null) {
            appendLog("[!] clipboard unavailable");
            return;
        }
        clipboard.setPrimaryClip(
                ClipData.newPlainText("Galaxy XR Root Manager log", String.join("\n", logBuffer)));
        appendLog("[*] log copied to clipboard (" + logBuffer.size() + " lines)");
    }

    /** Brings the log card into view when a run starts, so its output is never off-screen. */
    private void scrollToLog() {
        if (pageScroll == null || logCard == null) return;
        pageScroll.post(() -> pageScroll.smoothScrollTo(0, Math.max(0, logCard.getTop() - dp(12))));
    }

    private void openDeveloperOptions() {
        if (!developerOptionsEnabled()) {
            appendLog("[!] developer options are off; wireless debugging and pairing live under them");
            danger("Developer options are off",
                    "Wireless debugging and pairing live under Developer options, and they are "
                            + "disabled right now.\n\nEnable them first: open Settings > General, "
                            + "then tap Build number 7 times in About. Developer options then "
                            + "appears in General.",
                    "Open General", this::openGeneralSettings);
            return;
        }
        try {
            Intent developer = new Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS);
            developer.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            ComponentName resolved = developer.resolveActivity(getPackageManager());
            /* This XR build answers the action with a stub screen
             * (DevelopmentSettingsDisabledActivity) while the real developer options
             * activity is disabled in its manifest. Only launch the intent when it
             * leads to real developer options. */
            if (resolved != null && !resolved.getClassName().contains("Disabled")) {
                startActivity(developer);
                return;
            }
        } catch (Throwable ignored) {
        }
        openGeneralSettings();
    }

    /** Settings > General — the closest exported page to Developer options on this XR build. */
    private void openGeneralSettings() {
        try {
            Intent general = new Intent();
            general.setClassName("com.android.settings",
                    "com.android.settings.Settings$GeneralDeviceSettingsActivity");
            /* A new task opens its own window on XR, so this app stays visible next to
             * Settings while pairing code and ports are copied between them. */
            general.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(general);
            return;
        } catch (Throwable failure) {
            appendLog("[!] cannot open General settings: " + failure.getClass().getSimpleName());
        }
        try {
            Intent settings = new Intent(Settings.ACTION_SETTINGS);
            settings.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(settings);
        } catch (Throwable failure) {
            appendLog("[!] cannot open Settings: " + failure);
        }
    }

    /** A denied Settings.Global read is treated as enabled so navigation never blocks. */
    private boolean developerOptionsEnabled() {
        try {
            return Settings.Global.getInt(getContentResolver(), "development_settings_enabled", 0) == 1;
        } catch (Throwable denied) {
            return true;
        }
    }

    private void danger(String title, String message, String confirm, Runnable action) {
        danger(title, message, confirm, action, false);
    }

    private void danger(String title, String message, String confirm, Runnable action,
                        boolean noOutsideCancel) {
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(title)
                .setMessage(message)
                .setNegativeButton("Cancel", null)
                .setPositiveButton(confirm, (which, nothing) -> {
                    if (action != null) action.run();
                })
                .show();
        if (noOutsideCancel) dialog.setCanceledOnTouchOutside(false);
        Button positive = dialog.getButton(AlertDialog.BUTTON_POSITIVE);
        positive.setFilterTouchesWhenObscured(true);
        positive.setOnTouchListener((view, event) -> (event.getFlags()
                & (MotionEvent.FLAG_WINDOW_IS_OBSCURED | MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED)) != 0);
    }

    private String versionName() {
        try {
            return getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
        } catch (Exception ignored) {
            return "unknown";
        }
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private TextView text(LinearLayout parent, String value, int size, int color, boolean bold) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextColor(color);
        view.setTextSize(size);
        if (bold) view.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        view.setTextIsSelectable(true);
        view.setPadding(0, dp(4), 0, dp(8));
        parent.addView(view, new LinearLayout.LayoutParams(-1, -2));
        return view;
    }

    private LinearLayout card(String title) {
        LinearLayout view = new LinearLayout(this);
        view.setOrientation(LinearLayout.VERTICAL);
        view.setPadding(dp(20), dp(16), dp(20), dp(16));
        GradientDrawable background = new GradientDrawable();
        background.setColor(CARD);
        background.setCornerRadius(dp(18));
        view.setBackground(background);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, -2);
        params.bottomMargin = dp(16);
        page.addView(view, params);
        text(view, title, 18, ACCENT, true);
        return view;
    }

    private Button button(LinearLayout parent, String label, boolean primary, View.OnClickListener click) {
        Button view = new Button(this);
        view.setText(label);
        view.setAllCaps(false);
        view.setTextSize(15);
        view.setTextColor(primary ? BACKGROUND : INK);
        view.setBackgroundColor(primary ? ACCENT : CARD);
        view.setMinHeight(dp(52));
        view.setFilterTouchesWhenObscured(true);
        if (click != null) view.setOnClickListener(click);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, -2);
        params.weight = 1f;
        params.setMargins(dp(4), dp(4), dp(4), dp(4));
        parent.addView(view, params);
        return view;
    }
}
