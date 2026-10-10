package dev.galaxyxr.rootmanager;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class SafetyPolicy {
    public static final String MODEL = "SM-I610";
    public static final String PRODUCT = "xrvst2ue";
    public static final String FINGERPRINT =
        "samsung/xrvst2ue/xrvst2:14/UML2.260301.001/I610UEU2AZF3:user/release-keys";
    public static final String KERNEL = "5.10.240-android12-9-perf-33775878-abI610UEU2AZF3";

    private SafetyPolicy() {}

    public static List<String> identityProblems(String model, String product, String fingerprint,
            String kernel, int sdk, long pageSize, boolean arm64) {
        List<String> problems = new ArrayList<>();
        if (!MODEL.equals(model)) problems.add("Model does not match the historical SM-I610 target.");
        if (!PRODUCT.equals(product)) problems.add("Product does not match the xrvst2ue target.");
        if (!FINGERPRINT.equals(fingerprint)) problems.add("Full firmware fingerprint does not match.");
        if (!KERNEL.equals(kernel)) problems.add("Exact kernel release does not match.");
        if (sdk != 34) problems.add("Historical target requires Android 14 / API 34.");
        if (pageSize != 4096) problems.add("Historical target requires 4096-byte pages.");
        if (!arm64) problems.add("ARM64 execution is unavailable.");
        return Collections.unmodifiableList(problems);
    }

    public static List<String> implementationBlockers() {
        List<String> blockers = new ArrayList<>();
        blockers.add("Root execution is not included in this diagnostic APK.");
        blockers.add("App-accessible kernel address discovery and CPU scheduling are unverified.");
        blockers.add("Normal app UID, SELinux, seccomp and resource compatibility are unverified.");
        blockers.add("Safe lifetime of retained kernel allocations is unverified.");
        blockers.add("Complete live rollback is unproven; removing future root requires reboot.");
        return Collections.unmodifiableList(blockers);
    }

    public static boolean canExecuteRoot() { return false; }
    public static boolean canEnableAutomaticRoot() { return false; }
    public static boolean canExecuteClientCommands() { return false; }
}
