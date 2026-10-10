package dev.galaxyxr.rootmanager;

import org.json.JSONObject;

/** Synthetic evaluator tests. These do not establish device root. */
public final class RootStatusTest {
    private static final String BOOT = "d055f29e-a994-4b88-a07b-b5a998f8faf1";
    private static final String OTHER_BOOT = "e055f29e-a994-4b88-a07b-b5a998f8faf1";
    private static final String OUTPUT = "GXR_UID\n0\nGXR_CONTEXT\nu:r:su:s0\nGXR_KERNEL\n"
        + "5.10.240-android12-9-perf\nGXR_BOOT_ID\n" + BOOT + "\nGXR_SELINUX\nEnforcing\n";
    private static int scenarios;
    private static int assertions;

    private static JSONObject positive() throws Exception {
        return new JSONObject().put("proof_format_version", 1).put("legacy_protocol_version", 1)
            .put("operation", "status").put("caller_uid", 10123)
            .put("peer_credentials_available", true).put("root_peer_authenticated", true)
            .put("peer_uid", 0).put("client_authorized", true).put("status_request_sent", true)
            .put("protocol_status", 0).put("stdout", OUTPUT).put("stderr", "")
            .put("error", JSONObject.NULL);
    }

    private static void expect(String name, JSONObject proof, String before, String after,
            String state) throws Exception {
        JSONObject result = RootStatus.assess(proof, before, after);
        check(state.equals(result.getString("state")), name + ": unexpected state " + result);
        check(result.get("verified_root") instanceof Boolean, name + ": boolean type");
        check(result.getBoolean("verified_root") == "verified_root".equals(state), name + ": root flag");
        check(!result.getString("reason").trim().isEmpty(), name + ": missing reason");
        check(result.has("proof") && result.get("proof") == (proof == null ? JSONObject.NULL : proof),
            name + ": missing original proof");
        scenarios++;
    }

    private static void check(boolean condition, String message) {
        assertions++;
        if (!condition) throw new AssertionError(message);
    }

    private static void reject(String name, JSONObject proof) throws Exception {
        expect(name, proof, BOOT, BOOT, "verification_failed");
    }

    public static void main(String[] ignored) throws Exception {
        expect("successful current boot", positive(), BOOT, BOOT, "verified_root");
        for (String selinux : new String[]{"Permissive", "Disabled"}) {
            expect("valid SELinux " + selinux, positive().put("stdout", OUTPUT.replace("Enforcing", selinux)),
                BOOT, BOOT, "verified_root");
        }
        for (String key : new String[]{"proof_format_version", "legacy_protocol_version", "operation",
                "peer_credentials_available", "root_peer_authenticated", "peer_uid", "client_authorized",
                "status_request_sent", "protocol_status", "error", "stdout"}) {
            JSONObject missing = positive();
            missing.remove(key);
            reject("missing " + key, missing);
        }
        for (String key : new String[]{"peer_credentials_available", "root_peer_authenticated",
                "client_authorized", "status_request_sent"}) {
            reject("integer flag " + key, positive().put(key, 1));
            reject("string flag " + key, positive().put(key, "true"));
            reject("null flag " + key, positive().put(key, JSONObject.NULL));
            reject("false flag " + key, positive().put(key, false));
        }
        for (String key : new String[]{"proof_format_version", "legacy_protocol_version"}) {
            reject("unknown " + key, positive().put(key, 2));
            reject("string " + key, positive().put(key, "1"));
            reject("fractional " + key, positive().put(key, 1.1));
        }
        reject("probe only", positive().put("operation", "probe"));
        reject("peer nonroot", positive().put("peer_uid", 2000));
        reject("string peer zero", positive().put("peer_uid", "0"));
        reject("status nonzero", positive().put("protocol_status", 1));
        reject("string status zero", positive().put("protocol_status", "0"));
        reject("status error", positive().put("error", "status_command_failed"));
        reject("string null error", positive().put("error", "null"));
        reject("false error", positive().put("error", false));

        for (String malformed : new String[]{"", OUTPUT.substring(0, OUTPUT.length() - 1), OUTPUT + "\n",
                OUTPUT + "unexpected\n", OUTPUT.replace("GXR_UID", "UNEXPECTED_UID"),
                OUTPUT.replace("\n0\n", "\n2000\n"), OUTPUT.replace("\n0\n", "\n00\n"),
                OUTPUT.replace("u:r:su:s0", ""), OUTPUT.replace("u:r:su:s0", " \t"),
                OUTPUT.replace("5.10.240-android12-9-perf", ""), OUTPUT.replace(BOOT, "invalid-boot"),
                OUTPUT.replace("Enforcing", "Unknown"), OUTPUT.replace("\n", "\r\n"),
                OUTPUT.replace("u:r:su:s0", "u:r:su:s0\0"), OUTPUT.replace("u:r:su:s0", "u:r:su:s0\nextra")}) {
            reject("malformed output " + scenarios, positive().put("stdout", malformed));
        }
        reject("different remote boot", positive().put("stdout", OUTPUT.replace(BOOT, OTHER_BOOT)));
        reject("non-string output", positive().put("stdout", 0));
        expect("restart during check", positive(), BOOT, OTHER_BOOT, "unverifiable");
        expect("missing before boot", positive(), null, BOOT, "unverifiable");
        expect("invalid after boot", positive(), BOOT, "not-a-uuid", "unverifiable");
        expect("trailing boot whitespace", positive(), BOOT + "\n", BOOT, "unverifiable");
        expect("no proof", null, BOOT, BOOT, "unverifiable");

        JSONObject denied = positive().put("client_authorized", false).put("status_request_sent", false)
            .put("protocol_status", JSONObject.NULL).put("stdout", "").put("error", "client_not_authorized");
        expect("authenticated denied manager", denied, BOOT, BOOT, "root_server_app_denied");
        reject("nonroot denial", new JSONObject(denied.toString()).put("peer_uid", 2000));
        reject("unauthenticated denial", new JSONObject(denied.toString()).put("root_peer_authenticated", false));
        reject("denial with command bytes", new JSONObject(denied.toString()).put("status_request_sent", true));
        for (String failure : new String[]{"connect_failed", "connect_timeout", "socket_failed"}) {
            JSONObject absent = positive().put("peer_credentials_available", false)
                .put("root_peer_authenticated", false).put("peer_uid", JSONObject.NULL)
                .put("client_authorized", false).put("status_request_sent", false)
                .put("protocol_status", JSONObject.NULL).put("stdout", "").put("error", failure);
            expect("unreachable " + failure, absent, BOOT, BOOT, "unverifiable");
            reject("contradictory " + failure, new JSONObject(absent.toString()).put("client_authorized", true));
        }
        reject("nonroot peer alone", positive().put("peer_uid", 2000).put("root_peer_authenticated", false)
            .put("client_authorized", false).put("status_request_sent", false)
            .put("protocol_status", JSONObject.NULL).put("stdout", "").put("error", "peer_not_root"));
        expect("prior success cannot cache", null, BOOT, BOOT, "unverifiable");
        System.out.println("Synthetic JVM root status: " + scenarios + " scenarios passed; " + assertions + " assertions");
    }
}
