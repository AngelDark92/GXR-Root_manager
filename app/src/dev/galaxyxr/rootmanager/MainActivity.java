package dev.galaxyxr.rootmanager;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.text.InputType;
import android.view.MotionEvent;
import android.view.View;
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
    private static final int LOG_LIMIT = 200;

    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private RootEngine engine;
    private LinearLayout page;
    private LinearLayout logCard;
    private TextView logPlaceholder;
    private TextView statusView;
    private TextView statusDetail;
    private TextView ksuView;
    private Button rootButton;
    private Button verifyButton;
    private boolean busy;
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
    }

    @Override
    protected void onResume() {
        super.onResume();
        showStoredStatus();
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
        if (engine.pairCode().isEmpty()) {
            appendLog("[!] pairing code missing");
            danger("Pairing code required",
                    "Pairing is required on this build. On the headset open Developer options > Wireless "
                            + "debugging > Pair device with pairing code, then set the code and port in the "
                            + "Pairing card and press Pair now.",
                    "Got it", null);
            return;
        }
        setBusy(true);
        appendLog("[*] supervised root attempt for this boot");
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
        savePairing(pairCode, pairPort);
        String code = engine.pairCode();
        if (code.isEmpty()) {
            appendLog("[!] enter the pairing code first");
            return;
        }
        appendLog("[*] pairing");
        worker.execute(() -> {
            try {
                int port = engine.pairPort();
                if (port <= 0) {
                    List<Integer> ports = PortDiscovery.discoverPairingPorts(this, 10000, this::appendLog);
                    if (ports.isEmpty()) {
                        appendLog("[!] no pairing port advertised; is the pairing dialog open?");
                        return;
                    }
                    port = ports.get(0);
                    engine.setPairPort(port);
                    int found = port;
                    runOnUiThread(() -> pairPort.setText(String.valueOf(found)));
                }
                String output = engine.pair("localhost", port, code);
                appendLog("    " + output.replace("\n", " "));
            } catch (Exception failure) {
                appendLog("[!] pair failed: " + failure.getMessage());
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
            });
        });
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
                + "\nAn unavailable check does not mean the device has no root.");
    }

    private void setBusy(boolean value) {
        busy = value;
        if (rootButton != null) rootButton.setEnabled(!value);
        if (verifyButton != null) verifyButton.setEnabled(!value);
        for (Button button : gatedButtons) button.setEnabled(!value);
    }

    // ---------- page ----------

    private void showPage() {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(BACKGROUND);
        page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(dp(24), dp(24), dp(24), dp(32));
        scroll.addView(page, new ScrollView.LayoutParams(-1, -2));
        setContentView(scroll);

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
        gatedButtons.add(button(root, "Get the KernelSU module", false, ignored -> openKernelSuPage()));

        CheckBox autoBoot = new CheckBox(this);
        autoBoot.setText("Re-root after every restart");
        autoBoot.setTextColor(INK);
        autoBoot.setTextSize(15);
        autoBoot.setChecked(RootService.autoBoot(this));
        autoBoot.setOnCheckedChangeListener((view, checked) -> {
            RootService.setAutoBoot(this, checked);
            appendLog(checked ? "[*] boot re-root enabled" : "[*] boot re-root disabled");
        });
        root.addView(autoBoot, new LinearLayout.LayoutParams(-1, -2));

        if (checkSelfPermission("android.permission.WRITE_SECURE_SETTINGS")
                != PackageManager.PERMISSION_GRANTED) {
            text(root, "Unattended restarts need a one-time grant from a shell:\n"
                    + "pm grant dev.galaxyxr.rootmanager android.permission.WRITE_SECURE_SETTINGS",
                    13, WARN, false);
        }

        LinearLayout pairing = card("Pairing");
        text(pairing, "Pairing is required on this build. On the headset open Developer options > "
                + "Wireless debugging > Pair device with pairing code, keep that dialog open, then use "
                + "Find port and Pair now here.", 14, MUTED, false);
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
        logPlaceholder = text(logCard, "No run yet.", 13, MUTED, false);

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
        }));

        LinearLayout removal = card("Remove");
        text(removal, "Uninstall removes the app only. Root is kernel-memory only and disappears at "
                + "the next restart either way.", 14, MUTED, false);
        button(removal, "Uninstall this app", true, ignored -> danger("Uninstall Root Manager?",
                "Android will ask you to confirm.", "Uninstall", () -> startActivity(
                        new Intent(Intent.ACTION_DELETE, Uri.parse("package:" + getPackageName())))));

        showStoredStatus();
    }

    private void confirmRoot() {
        danger("Run the root exploit now?",
                "One attempt in this boot. It sets SELinux permissive for this boot and clears "
                        + "panic_on_oops. Keep Wireless debugging on. If the headset shows "
                        + "\"Allow wireless debugging?\", tap Always allow. A kernel exploit can "
                        + "crash the device; if it hangs, restart the headset.",
                "Root now", this::startRoot);
    }

    // ---------- helpers ----------

    private void appendLog(String line) {
        if (line == null || line.trim().isEmpty()) return;
        runOnUiThread(() -> {
            if (logCard == null) return;
            if (logPlaceholder != null) {
                logCard.removeView(logPlaceholder);
                logPlaceholder = null;
            }
            text(logCard, line, 13, line.startsWith("[+]") ? ACCENT : MUTED, false);
            while (logCard.getChildCount() > LOG_LIMIT + 1) logCard.removeViewAt(1);
        });
    }

    private void danger(String title, String message, String confirm, Runnable action) {
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(title)
                .setMessage(message)
                .setNegativeButton("Cancel", null)
                .setPositiveButton(confirm, (which, nothing) -> {
                    if (action != null) action.run();
                })
                .show();
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
