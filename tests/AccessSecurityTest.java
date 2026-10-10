package dev.galaxyxr.rootmanager;

import android.app.PendingIntent;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Binder;
import android.os.Bundle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.json.JSONArray;
import org.json.JSONObject;

public final class AccessSecurityTest {
    private static final int MANAGER = 10000;
    private static final int CALLER = 30001;
    private static final int OTHER = 30002;
    private static Path fixtureRoot;
    private static int scenarios;
    private static int assertions;

    private interface TestBody { void run(Fixture fixture) throws Exception; }
    private interface Operation { void run() throws Exception; }

    private static final class Fixture {
        final PackageManager packages = new PackageManager();
        final Path directory;
        final Context context;
        final AccessStore store;
        final AccessProvider provider = new AccessProvider();

        Fixture() throws Exception {
            directory = fixtureRoot.resolve(Integer.toString(scenarios));
            Files.createDirectories(directory);
            packages.register(CALLER, "test.caller", "caller-certificate");
            packages.register(OTHER, "test.other", "other-certificate");
            context = new Context(directory.toFile(), packages);
            store = new AccessStore(context);
            provider.attachContext(context);
            check(provider.onCreate(), "provider initialization");
            Binder.callerUid = CALLER;
        }

        JSONArray entries() {
            Binder.callerUid = MANAGER;
            JSONArray entries = store.list().getJSONArray("requests");
            Binder.callerUid = CALLER;
            return entries;
        }

        String approve() {
            Binder.callerUid = CALLER;
            String id = store.recordRequest(CALLER);
            Binder.callerUid = MANAGER;
            store.setDecision(id, true);
            Binder.callerUid = CALLER;
            equal("allow", store.status(CALLER), "manager approval applies");
            return id;
        }

        void writeLedger(JSONObject ledger) throws Exception {
            Files.writeString(directory.resolve("access-ledger.json"), ledger.toString(), StandardCharsets.UTF_8);
        }

        JSONObject ledger() throws Exception {
            return new JSONObject(Files.readString(directory.resolve("access-ledger.json"), StandardCharsets.UTF_8));
        }
    }

    private static void check(boolean value, String message) {
        assertions++;
        if (!value) throw new AssertionError(message);
    }

    private static void equal(Object expected, Object actual, String message) {
        check(expected.equals(actual), message + ": expected=" + expected + ", actual=" + actual);
    }

    private static void security(String message, Operation operation) throws Exception {
        try {
            operation.run();
        } catch (SecurityException rejected) {
            equal(message, rejected.getMessage(), "security rejection");
            return;
        }
        throw new AssertionError("Expected SecurityException: " + message);
    }

    private static void unknown(Operation operation) throws Exception {
        try {
            operation.run();
        } catch (IllegalArgumentException rejected) {
            equal("UNKNOWN_METHOD", rejected.getMessage(), "unknown provider method");
            return;
        }
        throw new AssertionError("Expected UNKNOWN_METHOD");
    }

    private static void scenario(String name, TestBody body) throws Exception {
        scenarios++;
        try {
            body.run(new Fixture());
        } catch (Exception | AssertionError failure) {
            throw new AssertionError("Scenario failed: " + name, failure);
        }
    }

    public static void main(String[] arguments) throws Exception {
        fixtureRoot = Path.of(arguments[0]);
        scenario("default denial, caller request, repeated request deduplication", f -> {
            equal("deny", f.store.status(CALLER), "default decision");
            String first = f.store.recordRequest(CALLER);
            equal("pending", f.store.status(CALLER), "request starts pending");
            equal(first, f.store.recordRequest(CALLER), "duplicate request ID");
            equal(1, f.entries().length(), "duplicate request count");
            equal("diagnostic-preview-v1", f.ledger().getString("capability"), "persisted diagnostic capability");
        });
        scenario("manager approval persists and can be denied", f -> {
            String id = f.approve();
            equal("allow", new AccessStore(f.context).status(CALLER), "persisted approval");
            Binder.callerUid = MANAGER;
            f.store.setDecision(id, false);
            Binder.callerUid = CALLER;
            equal("deny", f.store.status(CALLER), "explicit denial");
            equal(id, f.store.recordRequest(CALLER), "retry denied request retains ID");
            equal("pending", f.store.status(CALLER), "retry requires new approval");
        });
        scenario("external callers cannot administer grants", f -> {
            String id = f.store.recordRequest(CALLER);
            security("MANAGER_ONLY", () -> f.store.setDecision(id, true));
            security("MANAGER_ONLY", () -> f.store.list());
            security("MANAGER_ONLY", () -> f.store.revokeAll());
            security("MANAGER_ONLY", () -> f.store.resetPreviewLedger());
            equal("pending", f.store.status(CALLER), "failed administration preserves pending state");
        });
        scenario("UID spoofing rejected", f -> {
            security("CALLER_UID_MISMATCH", () -> f.store.recordRequest(OTHER));
            security("CALLER_UID_MISMATCH", () -> f.store.status(OTHER));
            security("CALLER_UID_MISMATCH", () -> f.store.recordRequest(-1));
            equal(0, f.entries().length(), "spoofing never creates ledger entry");
        });
        scenario("multiple packages sharing UID rejected", f -> {
            f.packages.uidPackages.put(CALLER, new String[]{"test.caller", "test.other"});
            security("UNKNOWN_OR_SHARED_UID", () -> f.store.recordRequest(CALLER));
            equal("deny", f.store.status(CALLER), "shared UID denied");
        });
        scenario("declared shared UID rejected", f -> {
            f.packages.infos.get("test.caller").sharedUserId = "test.shared";
            security("UNSUPPORTED_CALLER_IDENTITY", () -> f.store.recordRequest(CALLER));
            equal("deny", f.store.status(CALLER), "declared shared UID denied");
        });
        scenario("certificate replacement invalidates persisted grant", f -> {
            f.approve();
            f.packages.register(CALLER, "test.caller", "replacement-certificate");
            equal("deny", new AccessStore(f.context).status(CALLER), "new certificate denied");
            equal("deny", f.entries().getJSONObject(0).getString("decision"), "old grant revoked in ledger");
            f.packages.register(CALLER, "test.caller", "caller-certificate");
            equal("deny", f.store.status(CALLER), "restoring certificate does not restore grant");
        });
        scenario("UID reassignment invalidates grant", f -> {
            f.approve();
            f.packages.register(CALLER, "test.replacement", "caller-certificate");
            equal("deny", f.store.status(CALLER), "reassigned UID denied");
            equal("deny", f.entries().getJSONObject(0).getString("decision"), "reassigned old grant revoked");
        });
        scenario("package moved to different UID denied", f -> {
            f.approve();
            f.packages.infos.get("test.caller").applicationInfo.uid = OTHER;
            equal("deny", f.store.status(CALLER), "application UID mismatch denied");
            security("UNSUPPORTED_CALLER_IDENTITY", () -> f.store.recordRequest(CALLER));
        });
        scenario("unknown callers denied", f -> {
            Binder.callerUid = 39999;
            equal("deny", f.store.status(39999), "unknown UID status");
            security("UNKNOWN_OR_SHARED_UID", () -> f.store.recordRequest(39999));
        });
        scenario("uninstalled callers denied and old grant invalidated", f -> {
            f.approve();
            f.packages.infos.remove("test.caller");
            equal("deny", f.store.status(CALLER), "uninstalled package denied");
            equal("deny", f.entries().getJSONObject(0).getString("decision"), "uninstalled grant revoked");
        });
        for (String kind : new String[]{"missing", "multiple", "empty", "two"}) {
            scenario("unsupported signing identity " + kind, f -> {
                PackageInfo info = f.packages.infos.get("test.caller");
                if (kind.equals("missing")) info.signingInfo = null;
                if (kind.equals("multiple")) info.signingInfo.multiple = true;
                if (kind.equals("empty")) info.signingInfo.signers = new Signature[0];
                if (kind.equals("two")) info.signingInfo.signers = new Signature[]{new Signature("a"), new Signature("b")};
                equal("deny", f.store.status(CALLER), "unsupported signing status");
                security(kind.equals("empty") || kind.equals("two")
                    ? "UNSUPPORTED_CALLER_SIGNER" : "UNSUPPORTED_CALLER_IDENTITY",
                    () -> f.store.recordRequest(CALLER));
            });
        }
        scenario("corrupt ledger fails closed and revokeAll recovers", f -> {
            f.approve();
            Files.writeString(f.directory.resolve("access-ledger.json"), "{invalid", StandardCharsets.UTF_8);
            equal("deny", f.store.status(CALLER), "corrupt ledger denied");
            security("LEDGER_UNAVAILABLE", () -> f.store.recordRequest(CALLER));
            Binder.callerUid = MANAGER;
            equal("LEDGER_UNAVAILABLE", f.store.list().getString("error"), "corrupt list error");
            f.store.revokeAll();
            check(!f.store.list().has("error"), "revokeAll recovers ledger");
            equal(0, f.store.list().getJSONArray("requests").length(), "recovery ledger empty");
        });
        for (String kind : new String[]{"duplicate-id", "duplicate-identity", "version", "typed-uid", "decision", "hash"}) {
            scenario("malformed ledger " + kind + " fails closed", f -> {
                f.approve();
                JSONObject ledger = f.ledger();
                equal("diagnostic-preview-v1", ledger.getString("capability"), "malformed-entry fixture retains valid capability");
                JSONArray entries = ledger.getJSONArray("requests");
                JSONObject first = entries.getJSONObject(0);
                if (kind.equals("duplicate-id")) entries.put(new JSONObject(first.toString()));
                if (kind.equals("duplicate-identity")) {
                    JSONObject duplicate = new JSONObject(first.toString());
                    duplicate.put("id", java.util.UUID.randomUUID().toString());
                    entries.put(duplicate);
                }
                if (kind.equals("version")) ledger.put("version", 2);
                if (kind.equals("typed-uid")) first.put("uid", Integer.toString(CALLER));
                if (kind.equals("decision")) first.put("decision", "approved");
                if (kind.equals("hash")) first.put("certificate_sha256", "unverified");
                f.writeLedger(ledger);
                equal("deny", f.store.status(CALLER), "invalid ledger status");
                security("LEDGER_UNAVAILABLE", () -> f.store.recordRequest(CALLER));
                Binder.callerUid = MANAGER;
                equal("LEDGER_UNAVAILABLE", f.store.list().getString("error"), "invalid ledger list");
                security("LEDGER_UNAVAILABLE", () -> f.store.setDecision(first.getString("id"), true));
            });
        }
        scenario("trailing content and invalid UTF8 fail closed", f -> {
            f.approve();
            String ledger = f.ledger().toString();
            Files.writeString(f.directory.resolve("access-ledger.json"), ledger + " trailing", StandardCharsets.UTF_8);
            equal("deny", f.store.status(CALLER), "trailing content denied");
            Files.write(f.directory.resolve("access-ledger.json"), new byte[]{(byte) 0xc3, (byte) 0x28});
            equal("deny", f.store.status(CALLER), "invalid UTF8 denied");
        });
        scenario("manager revocation denies all existing grants", f -> {
            f.approve();
            Binder.callerUid = OTHER;
            String second = f.store.recordRequest(OTHER);
            Binder.callerUid = MANAGER;
            f.store.setDecision(second, true);
            f.store.revokeAll();
            Binder.callerUid = CALLER;
            equal("deny", f.store.status(CALLER), "first revoked");
            Binder.callerUid = OTHER;
            equal("deny", f.store.status(OTHER), "second revoked");
        });
        scenario("unknown request cannot be approved", f -> {
            Binder.callerUid = MANAGER;
            security("UNKNOWN_REQUEST", () -> f.store.setDecision("unknown", true));
            equal(0, f.store.list().getJSONArray("requests").length(), "no invented grant");
        });
        scenario("full ledger blocks requests until manager reset preserves reports", f -> {
            Path report = f.directory.resolve("diagnostic-report-sentinel.json");
            Files.writeString(report, "preserve this diagnostic evidence", StandardCharsets.UTF_8);
            for (int index = 0; index < 128; index++) {
                int uid = 40000 + index;
                f.packages.register(uid, "test.capacity." + index, "certificate-" + index);
                Binder.callerUid = uid;
                f.store.recordRequest(uid);
            }
            equal(128, f.entries().length(), "ledger reaches supported capacity");
            f.packages.register(50000, "test.capacity.overflow", "overflow-certificate");
            Binder.callerUid = 50000;
            security("ACCESS_LEDGER_FULL", () -> f.store.recordRequest(50000));
            security("MANAGER_ONLY", () -> f.store.resetPreviewLedger());
            equal(128, f.entries().length(), "external reset leaves full ledger intact");
            Binder.callerUid = MANAGER;
            f.store.resetPreviewLedger();
            equal(0, f.store.list().getJSONArray("requests").length(), "manager reset empties ledger");
            equal("diagnostic-preview-v1", f.ledger().getString("capability"), "reset retains diagnostic-only capability");
            equal("preserve this diagnostic evidence", Files.readString(report, StandardCharsets.UTF_8), "reset preserves diagnostic report");
            Binder.callerUid = 40000;
            equal("deny", f.store.status(40000), "reset discards prior preview decision");
            Binder.callerUid = 50000;
            Bundle extras = new Bundle();
            extras.putBoolean("allow", true);
            extras.putString("decision", "allow");
            extras.putString("approval_scope", "root");
            Bundle request = f.provider.call("requestAccess", "allow", extras);
            check(request.getString("request_id") != null, "new request succeeds after reset");
            equal("pending", f.store.status(50000), "new request requires manager approval despite extras");
            equal("diagnostic_preview", request.getString("approval_scope"), "reset never promotes approval scope");
            Binder.callerUid = MANAGER;
            equal(1, f.store.list().getJSONArray("requests").length(), "post-reset ledger contains only new request");
        });
        for (String kind : new String[]{"missing", "wrong"}) {
            scenario("ledger capability " + kind + " fails closed", f -> {
                String id = f.approve();
                JSONObject ledger = f.ledger();
                equal("diagnostic-preview-v1", ledger.getString("capability"), "original ledger capability");
                if (kind.equals("missing")) ledger.remove("capability");
                else ledger.put("capability", "root-execution-v1");
                f.writeLedger(ledger);
                equal("deny", new AccessStore(f.context).status(CALLER), "unsupported capability cannot reuse approval");
                security("LEDGER_UNAVAILABLE", () -> f.store.recordRequest(CALLER));
                Binder.callerUid = MANAGER;
                equal("LEDGER_UNAVAILABLE", f.store.list().getString("error"), "unsupported capability list rejected");
                security("LEDGER_UNAVAILABLE", () -> f.store.setDecision(id, true));
                f.store.resetPreviewLedger();
                equal(0, f.store.list().getJSONArray("requests").length(), "reset recovers unsupported capability ledger");
                equal("diagnostic-preview-v1", f.ledger().getString("capability"), "reset writes supported capability");
            });
        }
        scenario("every provider response declares diagnostic preview scope", f -> {
            Bundle extras = new Bundle();
            extras.putString("approval_scope", "root");
            extras.putString("capability", "root-execution-v1");
            extras.putBoolean("allow", true);
            for (String method : new String[]{"getStatus", "requestAccess", "getAccess", "execute"}) {
                Bundle result = f.provider.call(method, "allow", extras);
                equal("diagnostic_preview", result.getString("approval_scope"), "scope for " + method);
            }
            equal("pending", f.store.status(CALLER), "scope extras cannot grant access");
            f.approve();
            equal("diagnostic_preview", f.provider.call("getAccess", null, null).getString("approval_scope"), "approved decision remains preview scope");
        });
        scenario("provider status remains diagnostic regardless of extras", f -> {
            Bundle extras = new Bundle();
            extras.putBoolean("root_available", true);
            extras.putBoolean("boot_restore_enabled", true);
            Bundle status = f.provider.call("getStatus", "enable", extras);
            equal("diagnostic_only", status.getString("status"), "diagnostic status");
            check(!status.getBoolean("root_available"), "root unavailable");
            check(!status.getBoolean("boot_restore_enabled"), "boot restore unavailable");
        });
        scenario("provider execute unavailable before and after approval", f -> {
            equal("ROOT_BACKEND_UNAVAILABLE", f.provider.call("execute", "id", null).getString("error"), "unapproved execute");
            f.approve();
            Bundle extras = new Bundle();
            extras.putBoolean("allow", true);
            extras.putString("command", "enable_root_and_boot");
            equal("ROOT_BACKEND_UNAVAILABLE", f.provider.call("execute", "enable", extras).getString("error"), "approved execute");
            Bundle status = f.provider.call("getStatus", null, null);
            check(!status.getBoolean("root_available") && !status.getBoolean("boot_restore_enabled"), "execute never enables backend");
        });
        scenario("provider ignores caller UID and approval extras", f -> {
            Bundle extras = new Bundle();
            extras.putInt("uid", OTHER);
            extras.putBoolean("allow", true);
            extras.putString("decision", "allow");
            Bundle request = f.provider.call("requestAccess", "approve", extras);
            equal("pending", f.provider.call("getAccess", null, null).getString("decision"), "extras do not approve");
            JSONObject entry = f.entries().getJSONObject(0);
            equal(CALLER, entry.getInt("uid"), "request identity from Binder");
            equal("test.caller", entry.getString("package_name"), "request package from PackageManager");
            equal(entry.getString("id"), request.getString("request_id"), "provider request ID matches ledger");
            Binder.callerUid = OTHER;
            equal("deny", f.store.status(OTHER), "spoofed UID has no request");
        });
        scenario("provider getAccess bound to current Binder caller", f -> {
            f.approve();
            Binder.callerUid = OTHER;
            Bundle extras = new Bundle();
            extras.putInt("uid", CALLER);
            extras.putString("package_name", "test.caller");
            equal("deny", f.provider.call("getAccess", Integer.toString(CALLER), extras).getString("decision"), "other caller cannot borrow approved identity");
            Binder.callerUid = CALLER;
            equal("allow", f.provider.call("getAccess", null, null).getString("decision"), "approved caller retains grant");
        });
        scenario("approval PendingIntent immutable with unique request data", f -> {
            Bundle first = f.provider.call("requestAccess", null, null);
            PendingIntent approval = (PendingIntent) first.getParcelable("approval_intent");
            check((approval.flags & PendingIntent.FLAG_IMMUTABLE) != 0, "immutable PendingIntent flag");
            check((approval.flags & PendingIntent.FLAG_UPDATE_CURRENT) != 0, "update existing PendingIntent flag");
            equal(MainActivity.class, approval.intent.target, "explicit manager activity");
            equal("dev.galaxyxr.rootmanager.REVIEW_ACCESS", approval.intent.action, "review action");
            equal(first.getString("request_id"), approval.intent.extras.get("request_id"), "review request extra");
            equal("content://dev.galaxyxr.rootmanager.access/requests/" + first.getString("request_id"), approval.intent.data.toString(), "request-specific URI");
            Binder.callerUid = OTHER;
            Bundle second = f.provider.call("requestAccess", null, null);
            PendingIntent other = (PendingIntent) second.getParcelable("approval_intent");
            check(!approval.intent.data.toString().equals(other.intent.data.toString()), "different caller request identities");
            Binder.callerUid = CALLER;
            Bundle repeated = f.provider.call("requestAccess", null, null);
            equal(first.getString("request_id"), repeated.getString("request_id"), "provider request deduplication");
        });
        scenario("provider unknown methods cannot administer access", f -> {
            for (String method : new String[]{"setDecision", "list", "revokeAll", "resetPreviewLedger", "enableRoot", "enableBootRestore", "uninstall", "unknown"}) {
                unknown(() -> f.provider.call(method, "allow", new Bundle()));
            }
            unknown(() -> f.provider.call(null, null, null));
            equal("deny", f.store.status(CALLER), "unknown methods never grant access");
        });
        scenario("provider file and CRUD entrypoints remain closed", f -> {
            for (Operation operation : new Operation[]{
                () -> f.provider.query(null, null, null, null, null),
                () -> f.provider.insert(null, null),
                () -> f.provider.update(null, null, null, null),
                () -> f.provider.delete(null, null, null),
                () -> f.provider.openFile(null, "rw")
            }) {
                try {
                    operation.run();
                } catch (UnsupportedOperationException rejected) {
                    equal("CALL_ONLY", rejected.getMessage(), "unsupported provider access");
                    continue;
                }
                throw new AssertionError("Provider exposed unsupported entrypoint");
            }
            check(f.provider.getType(null) == null, "no provider MIME type");
            check(!new AccessProvider().onCreate(), "missing context rejected");
        });
        System.out.println("Synthetic JVM access security: " + scenarios + " scenarios passed, " + assertions + " assertions.");
    }
}
