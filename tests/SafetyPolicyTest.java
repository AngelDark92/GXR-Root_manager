import dev.galaxyxr.rootmanager.SafetyPolicy;
import java.util.List;

public final class SafetyPolicyTest {
    private static int checks;

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }

    public static void main(String[] args) {
        check(SafetyPolicy.identityProblems(SafetyPolicy.MODEL, SafetyPolicy.PRODUCT,
            SafetyPolicy.FINGERPRINT, SafetyPolicy.KERNEL, 34, 4096, true).isEmpty(), "exact identity");
        check(!SafetyPolicy.identityProblems("SM-I610", SafetyPolicy.PRODUCT, SafetyPolicy.FINGERPRINT,
            "5.10.240", 34, 4096, true).isEmpty(), "short kernel is insufficient");
        check(!SafetyPolicy.identityProblems("SM-I610", SafetyPolicy.PRODUCT, "I610UEU2AZF3",
            SafetyPolicy.KERNEL, 34, 4096, true).isEmpty(), "incremental is insufficient");
        check(!SafetyPolicy.identityProblems("other", SafetyPolicy.PRODUCT, SafetyPolicy.FINGERPRINT,
            SafetyPolicy.KERNEL, 34, 4096, true).isEmpty(), "model mismatch");
        check(!SafetyPolicy.identityProblems("SM-I610", "other", SafetyPolicy.FINGERPRINT,
            SafetyPolicy.KERNEL, 34, 4096, true).isEmpty(), "product mismatch");
        check(!SafetyPolicy.identityProblems("SM-I610", SafetyPolicy.PRODUCT, SafetyPolicy.FINGERPRINT,
            SafetyPolicy.KERNEL, 35, 4096, true).isEmpty(), "API mismatch");
        check(!SafetyPolicy.identityProblems("SM-I610", SafetyPolicy.PRODUCT, SafetyPolicy.FINGERPRINT,
            SafetyPolicy.KERNEL, 34, 16384, true).isEmpty(), "page mismatch");
        check(!SafetyPolicy.identityProblems("SM-I610", SafetyPolicy.PRODUCT, SafetyPolicy.FINGERPRINT,
            SafetyPolicy.KERNEL, 34, 4096, false).isEmpty(), "ABI mismatch");
        List<String> liveIdentityProblems = SafetyPolicy.identityProblems("SM-I610", "xrvst2ue",
            "samsung/xrvst2ue/xrvst2:14/UML.260301.001/I610UEU2AZF3:user/release-keys",
            SafetyPolicy.KERNEL, 34, 4096, true);
        check(liveIdentityProblems.size() == 1, "historical lookalike fingerprint must be rejected");
        check(liveIdentityProblems.contains("Full firmware fingerprint does not match."),
            "UML2 requires independent exact-build evidence");
        List<String> deviceAsProductProblems = SafetyPolicy.identityProblems("SM-I610", "xrvst2",
            SafetyPolicy.FINGERPRINT, SafetyPolicy.KERNEL, 34, 4096, true);
        check(deviceAsProductProblems.size() == 1
            && deviceAsProductProblems.contains("Product does not match the xrvst2ue target."),
            "device codename cannot substitute for product");
        check(!SafetyPolicy.canExecuteRoot(), "matching identity never authorizes an exploit");
        check(!SafetyPolicy.canEnableAutomaticRoot(), "automatic root disabled");
        check(!SafetyPolicy.canExecuteClientCommands(), "approval never authorizes unavailable root");
        check(SafetyPolicy.implementationBlockers().size() >= 4, "missing safety evidence stays visible");
        System.out.println("SafetyPolicy: " + checks + " checks passed");
    }
}
