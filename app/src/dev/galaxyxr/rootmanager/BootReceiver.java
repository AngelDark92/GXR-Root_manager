package dev.galaxyxr.rootmanager;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

/**
 * Re-arms the supervised root flow once per boot. Root is kernel-memory only,
 * so it must be re-obtained after every restart.
 */
public final class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent == null ? null : intent.getAction();
        if (action == null) return;
        if (!Intent.ACTION_BOOT_COMPLETED.equals(action)
                && !Intent.ACTION_LOCKED_BOOT_COMPLETED.equals(action)
                && !Intent.ACTION_MY_PACKAGE_REPLACED.equals(action)) {
            return;
        }
        if (!SafetyPolicy.FINGERPRINT.equals(Build.FINGERPRINT)) return;
        if (!RootService.autoBoot(context)) return;
        Intent service = new Intent(context, RootService.class);
        service.putExtra(RootService.EXTRA_TRIGGER, action);
        try {
            context.startForegroundService(service);
        } catch (Throwable failure) {
            android.util.Log.w("gxr-boot", "boot root service refused: " + failure);
        }
    }
}
