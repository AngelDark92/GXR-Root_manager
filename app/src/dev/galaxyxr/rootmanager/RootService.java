package dev.galaxyxr.rootmanager;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.IBinder;
import android.os.PowerManager;
import android.provider.Settings;

import org.json.JSONObject;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Foreground worker that re-runs the supervised root flow at boot.
 * Android 12+ exempts BOOT_COMPLETED from the background foreground-service
 * start restriction, and Android 14 requires a declared service type.
 */
public final class RootService extends Service {
    static final String EXTRA_TRIGGER = "trigger";
    static final String PREFS = "gxr";
    static final String AUTO_BOOT = "auto_boot";
    private static final String CHANNEL = "gxr-root";
    private static final int NOTIFICATION_ID = 4701;

    private static final AtomicBoolean RUNNING = new AtomicBoolean();

    private RootEngine engine;
    private PowerManager.WakeLock wakeLock;

    static boolean autoBoot(Context context) {
        return prefs(context).getBoolean(AUTO_BOOT, true);
    }

    static void setAutoBoot(Context context, boolean enabled) {
        prefs(context).edit().putBoolean(AUTO_BOOT, enabled).apply();
    }

    private static SharedPreferences prefs(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) {
            NotificationChannel channel = new NotificationChannel(CHANNEL, "Root", NotificationManager.IMPORTANCE_LOW);
            channel.setShowBadge(false);
            manager.createNotificationChannel(channel);
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (!RUNNING.compareAndSet(false, true)) return START_NOT_STICKY;
        startForeground(NOTIFICATION_ID, notification("Checking root"));
        try {
            PowerManager power = getSystemService(PowerManager.class);
            if (power != null) {
                wakeLock = power.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "gxr:boot");
                wakeLock.acquire(20 * 60 * 1000L);
            }
        } catch (Throwable ignored) {
        }
        Thread worker = new Thread(this::runFlow, "gxr-boot");
        worker.setDaemon(true);
        worker.start();
        return START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        release();
        RUNNING.set(false);
        super.onDestroy();
    }

    private void runFlow() {
        engine = new RootEngine(this);
        try {
            enableWirelessDebugging();
        } catch (Throwable ignored) {
        }
        try {
            JSONObject already = engine.verifyRoot();
            if ("verified_root".equals(already.optString("state"))) {
                finish("Root already active", true);
                return;
            }
        } catch (Throwable ignored) {
        }
        engine.runRoot(this::stage, () -> {
            JSONObject check;
            try {
                check = engine.verifyRoot();
            } catch (Throwable failure) {
                check = new JSONObject();
            }
            boolean rooted = "verified_root".equals(check.optString("state"));
            finish(rooted ? "Root active for this boot" : "Re-root failed; open the app", rooted);
        });
    }

    private void stage(String line) {
        String text = line == null ? "" : line.replace("[+]", "").trim();
        if (text.startsWith("verifying") || text.startsWith("launching") || text.startsWith("pushing")) {
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) manager.notify(NOTIFICATION_ID, notification(text));
        }
    }

    private void finish(String text, boolean rooted) {
        try {
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) manager.notify(NOTIFICATION_ID, notification(text));
        } catch (Throwable ignored) {
        }
        release();
        if (engine != null) engine.shutdown();
        stopForeground(STOP_FOREGROUND_DETACH);
        stopSelf();
    }

    private Notification notification(String text) {
        return new Notification.Builder(this, CHANNEL)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentTitle("Galaxy XR Root")
                .setContentText(text)
                .setOngoing(false)
                .build();
    }

    private void release() {
        PowerManager.WakeLock held = wakeLock;
        wakeLock = null;
        if (held != null && held.isHeld()) {
            try {
                held.release();
            } catch (Throwable ignored) {
            }
        }
    }

    /** Best-effort: keep the wireless-debugging TLS server up across boots. */
    void enableWirelessDebugging() {
        try {
            Settings.Global.putInt(getContentResolver(), "adb_wifi_enabled", 1);
        } catch (Throwable denied) {
            // WRITE_SECURE_SETTINGS not granted; the boot flow still proceeds.
        }
        try {
            Settings.Global.putLong(getContentResolver(), "adb_allowed_connection_time", 604800000L * 52);
        } catch (Throwable denied) {
        }
    }
}
