package dev.galaxyxr.rootmanager;

import android.os.Build;
import android.os.Process;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

public final class NativeDiagnostics {
    private NativeDiagnostics() {}

    private static native String inspect();
    private static native String verifyRootStatus();

    public static JSONObject collect() {
        JSONObject report = new JSONObject();
        try {
            SimpleDateFormat timestamp = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US);
            timestamp.setTimeZone(TimeZone.getTimeZone("UTC"));
            report.put("timestamp_utc", timestamp.format(new Date()));
            report.put("model", Build.MODEL);
            report.put("product", Build.PRODUCT);
            report.put("device", Build.DEVICE);
            report.put("fingerprint", Build.FINGERPRINT);
            report.put("supported_abis", new JSONArray(Build.SUPPORTED_ABIS));
            report.put("android_sdk", Build.VERSION.SDK_INT);
            report.put("app_uid", Process.myUid());
            report.put("observation", "App-context observations and fixed read-only root verification. Unavailable root verification does not establish global root absence. Positive opens do not establish exploit feasibility.");
            report.put("untested", new JSONArray(new String[] {
                    "vulnerability", "OTA/snapshot state", "allocation keeper lifetime"
            }));
        } catch (Throwable error) {
            putError(report, "java_error", error);
        }
        JSONObject nativeReport = null;
        try {
            System.loadLibrary("gxr_diagnostics");
            String result = inspect();
            if (result == null) {
                report.put("native_error", "Native inspection returned no report");
            } else {
                nativeReport = new JSONObject(result);
                report.put("native", nativeReport);
            }
        } catch (Throwable error) {
            putError(report, "native_error", error);
        }
        try {
            JSONObject proof = new JSONObject(verifyRootStatus());
            JSONObject after = new JSONObject(inspect());
            JSONObject beforeBoot = nativeReport == null ? null : nativeReport.optJSONObject("boot_id");
            JSONObject afterBoot = after.optJSONObject("boot_id");
            report.put("root_verification", RootStatus.assess(proof,
                    beforeBoot == null ? null : beforeBoot.optString("value", null),
                    afterBoot == null ? null : afterBoot.optString("value", null)));
        } catch (Throwable error) {
            try {
                JSONObject unavailable = new JSONObject();
                unavailable.put("state", "unverifiable");
                unavailable.put("verified_root", false);
                unavailable.put("reason", "Root verification unavailable: " + error.getClass().getSimpleName());
                report.put("root_verification", unavailable);
            } catch (JSONException ignored) {
            }
        }
        return report;
    }

    private static void putError(JSONObject report, String key, Throwable error) {
        try {
            String message = error.getMessage();
            report.put(key, error.getClass().getSimpleName() + (message == null ? "" : ": " + message));
        } catch (JSONException ignored) {
        }
    }
}
