package dev.galaxyxr.rootmanager;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Binder;
import android.os.Process;
import android.util.AtomicFile;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.Locale;
import java.util.UUID;

public final class AccessStore {
    private static final Object LEDGER_LOCK = new Object();
    private static final int MAX_ENTRIES = 128;
    private static final int MAX_BYTES = 262144;
    private static final String CAPABILITY = "diagnostic-preview-v1";
    private final AtomicFile file;
    private final PackageManager packages;

    public AccessStore(Context context) {
        Context app = context.getApplicationContext();
        file = new AtomicFile(new File(app.getFilesDir(), "access-ledger.json"));
        packages = app.getPackageManager();
    }

    public synchronized JSONObject list() {
        managerOnly();
        synchronized (LEDGER_LOCK) {
            JSONObject result = new JSONObject();
            try {
                JSONArray entries = read();
                if (revalidate(entries)) write(entries);
                result.put("requests", entries);
            } catch (Exception failure) {
                try {
                    result.put("requests", new JSONArray());
                    result.put("error", "LEDGER_UNAVAILABLE");
                } catch (JSONException impossible) {
                    throw new IllegalStateException(impossible);
                }
            }
            return result;
        }
    }

    public synchronized String recordRequest(int uid) throws SecurityException {
        callerOnly(uid);
        synchronized (LEDGER_LOCK) {
            try {
                JSONObject identity = identity(uid);
                JSONArray entries = read();
                revalidate(entries);
                for (int i = 0; i < entries.length(); i++) {
                    JSONObject entry = entries.getJSONObject(i);
                    if (sameIdentity(entry, identity)) {
                        if ("deny".equals(entry.getString("decision"))) {
                            entry.put("decision", "pending");
                        }
                        write(entries);
                        return entry.getString("id");
                    }
                }
                if (entries.length() >= MAX_ENTRIES) {
                    throw new SecurityException("ACCESS_LEDGER_FULL");
                }
                identity.put("id", UUID.randomUUID().toString());
                identity.put("decision", "pending");
                entries.put(identity);
                write(entries);
                return identity.getString("id");
            } catch (SecurityException failure) {
                throw failure;
            } catch (Exception failure) {
                throw new SecurityException("LEDGER_UNAVAILABLE", failure);
            }
        }
    }

    public synchronized void setDecision(String requestId, boolean allow) throws SecurityException {
        managerOnly();
        synchronized (LEDGER_LOCK) {
            try {
                JSONArray entries = read();
                revalidate(entries);
                for (int i = 0; i < entries.length(); i++) {
                    JSONObject entry = entries.getJSONObject(i);
                    if (!entry.getString("id").equals(requestId)) continue;
                    if (allow && !validIdentity(entry)) {
                        entry.put("decision", "deny");
                        write(entries);
                        throw new SecurityException("CALLER_IDENTITY_CHANGED");
                    }
                    entry.put("decision", allow ? "allow" : "deny");
                    write(entries);
                    return;
                }
                throw new SecurityException("UNKNOWN_REQUEST");
            } catch (SecurityException failure) {
                throw failure;
            } catch (Exception failure) {
                throw new SecurityException("LEDGER_UNAVAILABLE", failure);
            }
        }
    }

    public synchronized void revokeAll() {
        managerOnly();
        synchronized (LEDGER_LOCK) {
            JSONArray entries;
            try {
                entries = read();
            } catch (Exception corrupt) {
                entries = new JSONArray();
            }
            try {
                for (int i = 0; i < entries.length(); i++) {
                    entries.getJSONObject(i).put("decision", "deny");
                }
                write(entries);
            } catch (Exception failure) {
                throw new SecurityException("LEDGER_UNAVAILABLE", failure);
            }
        }
    }

    public synchronized void resetPreviewLedger() {
        managerOnly();
        synchronized (LEDGER_LOCK) {
            try {
                write(new JSONArray());
            } catch (Exception failure) {
                throw new SecurityException("LEDGER_UNAVAILABLE", failure);
            }
        }
    }

    public synchronized String status(int uid) {
        callerOnly(uid);
        synchronized (LEDGER_LOCK) {
            try {
                JSONArray entries = read();
                if (revalidate(entries)) write(entries);
                JSONObject identity = identity(uid);
                for (int i = 0; i < entries.length(); i++) {
                    JSONObject entry = entries.getJSONObject(i);
                    if (sameIdentity(entry, identity)) return entry.getString("decision");
                }
            } catch (Exception unavailable) {
                return "deny";
            }
            return "deny";
        }
    }

    private void managerOnly() {
        if (Binder.getCallingUid() != Process.myUid()) {
            throw new SecurityException("MANAGER_ONLY");
        }
    }

    private void callerOnly(int uid) {
        if (uid < 0 || Binder.getCallingUid() != uid) {
            throw new SecurityException("CALLER_UID_MISMATCH");
        }
    }

    private JSONObject identity(int uid) throws Exception {
        String[] names = packages.getPackagesForUid(uid);
        if (names == null || names.length != 1) {
            throw new SecurityException("UNKNOWN_OR_SHARED_UID");
        }
        PackageInfo info = packages.getPackageInfo(names[0], PackageManager.GET_SIGNING_CERTIFICATES);
        if (info.applicationInfo == null || info.applicationInfo.uid != uid
                || !names[0].equals(info.packageName) || info.sharedUserId != null
                || info.signingInfo == null || info.signingInfo.hasMultipleSigners()) {
            throw new SecurityException("UNSUPPORTED_CALLER_IDENTITY");
        }
        Signature[] signers = info.signingInfo.getApkContentsSigners();
        if (signers == null || signers.length != 1) {
            throw new SecurityException("UNSUPPORTED_CALLER_SIGNER");
        }
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(signers[0].toByteArray());
        StringBuilder hash = new StringBuilder(64);
        for (byte value : digest) hash.append(String.format(Locale.ROOT, "%02x", value & 255));
        JSONObject result = new JSONObject();
        result.put("uid", uid);
        result.put("package_name", info.packageName);
        result.put("label", String.valueOf(packages.getApplicationLabel(info.applicationInfo)));
        result.put("certificate_sha256", hash.toString());
        return result;
    }

    private boolean sameIdentity(JSONObject first, JSONObject second) throws JSONException {
        return first.getInt("uid") == second.getInt("uid")
                && first.getString("package_name").equals(second.getString("package_name"))
                && first.getString("certificate_sha256").equals(second.getString("certificate_sha256"));
    }

    private boolean validIdentity(JSONObject entry) {
        try {
            return sameIdentity(entry, identity(entry.getInt("uid")));
        } catch (Exception unavailable) {
            return false;
        }
    }

    private boolean revalidate(JSONArray entries) throws JSONException {
        boolean changed = false;
        for (int i = 0; i < entries.length(); i++) {
            JSONObject entry = entries.getJSONObject(i);
            if (!validIdentity(entry) && !"deny".equals(entry.getString("decision"))) {
                entry.put("decision", "deny");
                changed = true;
            }
        }
        return changed;
    }

    private JSONArray read() throws IOException, JSONException {
        if (!file.getBaseFile().exists()
                && !new File(file.getBaseFile().getPath() + ".bak").exists()) return new JSONArray();
        byte[] bytes;
        try (FileInputStream input = file.openRead();
                ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] chunk = new byte[4096];
            int count;
            while ((count = input.read(chunk)) != -1) {
                if (output.size() + count > MAX_BYTES) throw new IOException("LEDGER_TOO_LARGE");
                output.write(chunk, 0, count);
            }
            bytes = output.toByteArray();
        }
        String text = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString();
        JSONTokener parser = new JSONTokener(text);
        Object parsed = parser.nextValue();
        if (!(parsed instanceof JSONObject) || parser.nextClean() != 0) {
            throw new JSONException("INVALID_LEDGER");
        }
        JSONObject ledger = (JSONObject) parsed;
        if (!(ledger.get("version") instanceof Integer) || ledger.getInt("version") != 1) {
            throw new JSONException("UNSUPPORTED_LEDGER");
        }
        if (!CAPABILITY.equals(ledger.optString("capability"))) {
            throw new JSONException("UNSUPPORTED_CAPABILITY");
        }
        JSONArray entries = ledger.getJSONArray("requests");
        if (entries.length() > MAX_ENTRIES) throw new JSONException("LEDGER_TOO_LARGE");
        HashSet<String> ids = new HashSet<>();
        HashSet<String> identities = new HashSet<>();
        for (int i = 0; i < entries.length(); i++) {
            JSONObject entry = entries.getJSONObject(i);
            for (String key : new String[] {"id", "package_name", "label", "certificate_sha256", "decision"}) {
                if (!(entry.get(key) instanceof String)) throw new JSONException("INVALID_LEDGER_ENTRY");
            }
            String id = entry.getString("id");
            if (!UUID.fromString(id).toString().equals(id) || !ids.add(id)
                    || !(entry.get("uid") instanceof Integer) || entry.getInt("uid") < 0
                    || !entry.getString("certificate_sha256").matches("[0-9a-f]{64}")
                    || !entry.getString("decision").matches("pending|allow|deny")) {
                throw new JSONException("INVALID_LEDGER_ENTRY");
            }
            String key = entry.getInt("uid") + ":" + entry.getString("package_name")
                    + ":" + entry.getString("certificate_sha256");
            if (!identities.add(key)) throw new JSONException("DUPLICATE_LEDGER_IDENTITY");
        }
        return entries;
    }

    private void write(JSONArray entries) throws IOException, JSONException {
        JSONObject ledger = new JSONObject();
        ledger.put("version", 1);
        ledger.put("capability", CAPABILITY);
        ledger.put("requests", entries);
        byte[] bytes = ledger.toString().getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_BYTES) throw new IOException("LEDGER_TOO_LARGE");
        FileOutputStream output = null;
        try {
            output = file.startWrite();
            output.write(bytes);
            file.finishWrite(output);
        } catch (IOException | RuntimeException failure) {
            if (output != null) file.failWrite(output);
            throw failure;
        }
    }
}
