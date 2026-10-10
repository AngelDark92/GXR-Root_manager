package dev.galaxyxr.rootmanager;

import java.math.BigDecimal;
import java.util.regex.Pattern;
import org.json.JSONException;
import org.json.JSONObject;

/** Evaluates a fresh, fixed read-only status proof; this never obtains root. */
public final class RootStatus {
    private static final Pattern BOOT_ID = Pattern.compile(
        "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");

    private RootStatus() {}

    public static JSONObject assess(JSONObject proof, String bootBefore, String bootAfter) {
        if (!validBootId(bootBefore) || !validBootId(bootAfter)) {
            return result("unverifiable", "The current boot identity is unavailable.", proof);
        }
        if (!bootBefore.equals(bootAfter)) {
            return result("unverifiable", "The device restarted during verification. Check again.", proof);
        }
        if (proof == null) {
            return result("unverifiable", "A fresh root verification result is unavailable.", null);
        }
        if (!numberEquals(proof.opt("proof_format_version"), 1)
                || !numberEquals(proof.opt("legacy_protocol_version"), 1)
                || !"status".equals(proof.opt("operation"))
                || !(proof.opt("peer_credentials_available") instanceof Boolean)
                || !(proof.opt("root_peer_authenticated") instanceof Boolean)
                || !(proof.opt("client_authorized") instanceof Boolean)
                || !(proof.opt("status_request_sent") instanceof Boolean)
                || !proof.has("peer_uid") || !proof.has("protocol_status")
                || !proof.has("error") || !(proof.opt("stdout") instanceof String)) {
            return result("verification_failed", "The root verification result is incomplete or unsupported.", proof);
        }

        Object error = proof.opt("error");
        boolean peerKnown = Boolean.TRUE.equals(proof.opt("peer_credentials_available"));
        boolean peerRoot = Boolean.TRUE.equals(proof.opt("root_peer_authenticated"));
        boolean authorized = Boolean.TRUE.equals(proof.opt("client_authorized"));
        boolean requestSent = Boolean.TRUE.equals(proof.opt("status_request_sent"));
        String output = (String) proof.opt("stdout");
        boolean rootIdentity = peerKnown && peerRoot && numberEquals(proof.opt("peer_uid"), 0);

        if (("connect_failed".equals(error) || "connect_timeout".equals(error)
                || "socket_failed".equals(error)) && !peerKnown && !peerRoot && !authorized
                && !requestSent && proof.opt("peer_uid") == JSONObject.NULL
                && proof.opt("protocol_status") == JSONObject.NULL && output.isEmpty()) {
            return result("unverifiable", "The root server is not reachable. Root could not be verified.", proof);
        }
        if ("client_not_authorized".equals(error) && rootIdentity && !authorized
                && !requestSent && proof.opt("protocol_status") == JSONObject.NULL && output.isEmpty()) {
            return result("root_server_app_denied",
                "A root server was authenticated, but this manager is not authorized to use it.", proof);
        }
        if (!rootIdentity || !authorized || !requestSent
                || !numberEquals(proof.opt("protocol_status"), 0) || error != JSONObject.NULL) {
            return result("verification_failed", "The root server did not provide a successful authenticated status result.", proof);
        }

        String[] lines = output.split("\n", -1);
        if (output.indexOf('\0') >= 0 || output.indexOf('\r') >= 0 || lines.length != 11
                || !"GXR_UID".equals(lines[0]) || !"0".equals(lines[1])
                || !"GXR_CONTEXT".equals(lines[2]) || lines[3].trim().isEmpty()
                || !"GXR_KERNEL".equals(lines[4]) || lines[5].trim().isEmpty()
                || !"GXR_BOOT_ID".equals(lines[6]) || !validBootId(lines[7])
                || !"GXR_SELINUX".equals(lines[8])
                || !("Enforcing".equals(lines[9]) || "Permissive".equals(lines[9])
                    || "Disabled".equals(lines[9])) || !lines[10].isEmpty()) {
            return result("verification_failed", "The root status output is incomplete or malformed.", proof);
        }
        if (!bootBefore.equals(lines[7])) {
            return result("verification_failed", "The root status belongs to a different boot. Check again.", proof);
        }
        return result("verified_root", "Root was verified for this manager in the current boot.", proof);
    }

    private static boolean validBootId(String value) {
        return value != null && BOOT_ID.matcher(value).matches();
    }

    private static boolean numberEquals(Object value, int expected) {
        if (!(value instanceof Number)) return false;
        try {
            return new BigDecimal(value.toString()).compareTo(BigDecimal.valueOf(expected)) == 0;
        } catch (NumberFormatException invalid) {
            return false;
        }
    }

    private static JSONObject result(String state, String reason, JSONObject proof) {
        JSONObject result = new JSONObject();
        try {
            result.put("state", state);
            result.put("verified_root", "verified_root".equals(state));
            result.put("reason", reason);
            result.put("proof", proof == null ? JSONObject.NULL : proof);
            return result;
        } catch (JSONException impossible) {
            throw new IllegalStateException("Unable to represent root verification result", impossible);
        }
    }
}
