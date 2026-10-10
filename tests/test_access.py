import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
JSON_JAR = ROOT / ".local/testdeps/json-20240303.jar"
STUBS = {
    "android/os/Binder.java": """
        package android.os;
        public class Binder {
            public static int callerUid = 10000;
            public static int getCallingUid() { return callerUid; }
        }
    """,
    "android/os/Process.java": """
        package android.os;
        public class Process { public static int myUid() { return 10000; } }
    """,
    "android/os/Bundle.java": """
        package android.os;
        import java.util.HashMap;
        public class Bundle {
            private final HashMap<String, Object> values = new HashMap<>();
            public void putString(String key, String value) { values.put(key, value); }
            public void putBoolean(String key, boolean value) { values.put(key, value); }
            public void putInt(String key, int value) { values.put(key, value); }
            public void putParcelable(String key, Object value) { values.put(key, value); }
            public String getString(String key) { return (String) values.get(key); }
            public boolean getBoolean(String key) { return Boolean.TRUE.equals(values.get(key)); }
            public Object getParcelable(String key) { return values.get(key); }
        }
    """,
    "android/os/ParcelFileDescriptor.java": """
        package android.os;
        public class ParcelFileDescriptor {}
    """,
    "android/content/Context.java": """
        package android.content;
        import java.io.File;
        import android.content.pm.PackageManager;
        public class Context {
            private final File files;
            private final PackageManager packages;
            public Context(File files, PackageManager packages) {
                this.files = files;
                this.packages = packages;
            }
            public Context getApplicationContext() { return this; }
            public File getFilesDir() { return files; }
            public PackageManager getPackageManager() { return packages; }
        }
    """,
    "android/content/ContentProvider.java": """
        package android.content;
        import android.database.Cursor;
        import android.net.Uri;
        import android.os.Bundle;
        import android.os.ParcelFileDescriptor;
        public abstract class ContentProvider {
            private Context context;
            public void attachContext(Context context) { this.context = context; }
            public Context getContext() { return context; }
            public abstract boolean onCreate();
            public abstract Bundle call(String method, String arg, Bundle extras);
            public abstract Cursor query(Uri uri, String[] projection, String selection,
                String[] selectionArgs, String sortOrder);
            public abstract Uri insert(Uri uri, ContentValues values);
            public abstract int update(Uri uri, ContentValues values, String selection,
                String[] selectionArgs);
            public abstract int delete(Uri uri, String selection, String[] selectionArgs);
            public abstract ParcelFileDescriptor openFile(Uri uri, String mode);
            public abstract String getType(Uri uri);
        }
    """,
    "android/content/ContentValues.java": """
        package android.content;
        public class ContentValues {}
    """,
    "android/content/Intent.java": """
        package android.content;
        import android.net.Uri;
        import java.util.HashMap;
        public class Intent {
            public final Class<?> target;
            public String action;
            public Uri data;
            public final HashMap<String, String> extras = new HashMap<>();
            public Intent(Context context, Class<?> target) { this.target = target; }
            public Intent setAction(String action) { this.action = action; return this; }
            public Intent setData(Uri data) { this.data = data; return this; }
            public Intent putExtra(String key, String value) { extras.put(key, value); return this; }
        }
    """,
    "android/content/pm/ApplicationInfo.java": """
        package android.content.pm;
        public class ApplicationInfo { public int uid; public String label; }
    """,
    "android/content/pm/PackageInfo.java": """
        package android.content.pm;
        public class PackageInfo {
            public ApplicationInfo applicationInfo;
            public String packageName;
            public String sharedUserId;
            public SigningInfo signingInfo;
        }
    """,
    "android/content/pm/Signature.java": """
        package android.content.pm;
        import java.nio.charset.StandardCharsets;
        public class Signature {
            private final byte[] bytes;
            public Signature(String value) { bytes = value.getBytes(StandardCharsets.UTF_8); }
            public byte[] toByteArray() { return bytes.clone(); }
        }
    """,
    "android/content/pm/SigningInfo.java": """
        package android.content.pm;
        public class SigningInfo {
            public Signature[] signers;
            public boolean multiple;
            public SigningInfo(String certificate) { signers = new Signature[]{new Signature(certificate)}; }
            public boolean hasMultipleSigners() { return multiple; }
            public Signature[] getApkContentsSigners() { return signers; }
        }
    """,
    "android/content/pm/PackageManager.java": """
        package android.content.pm;
        import java.util.HashMap;
        public class PackageManager {
            public static final int GET_SIGNING_CERTIFICATES = 0x08000000;
            public final HashMap<Integer, String[]> uidPackages = new HashMap<>();
            public final HashMap<String, PackageInfo> infos = new HashMap<>();
            public String[] getPackagesForUid(int uid) { return uidPackages.get(uid); }
            public PackageInfo getPackageInfo(String name, int flags) {
                PackageInfo info = infos.get(name);
                if (info == null) throw new IllegalArgumentException("package unavailable");
                return info;
            }
            public CharSequence getApplicationLabel(ApplicationInfo info) { return info.label; }
            public void register(int uid, String name, String certificate) {
                PackageInfo info = new PackageInfo();
                info.packageName = name;
                info.applicationInfo = new ApplicationInfo();
                info.applicationInfo.uid = uid;
                info.applicationInfo.label = name;
                info.signingInfo = new SigningInfo(certificate);
                uidPackages.put(uid, new String[]{name});
                infos.put(name, info);
            }
        }
    """,
    "android/util/AtomicFile.java": """
        package android.util;
        import java.io.*;
        import java.nio.file.*;
        public class AtomicFile {
            private final File base;
            private final File backup;
            public AtomicFile(File base) { this.base = base; backup = new File(base + ".bak"); }
            public File getBaseFile() { return base; }
            public FileInputStream openRead() throws IOException {
                if (backup.exists()) Files.move(backup.toPath(), base.toPath(), StandardCopyOption.REPLACE_EXISTING);
                return new FileInputStream(base);
            }
            public FileOutputStream startWrite() throws IOException {
                if (base.exists()) Files.copy(base.toPath(), backup.toPath(), StandardCopyOption.REPLACE_EXISTING);
                return new FileOutputStream(base);
            }
            public void finishWrite(FileOutputStream stream) throws IOException {
                stream.close();
                Files.deleteIfExists(backup.toPath());
            }
            public void failWrite(FileOutputStream stream) {
                try {
                    stream.close();
                    if (backup.exists()) Files.move(backup.toPath(), base.toPath(), StandardCopyOption.REPLACE_EXISTING);
                    else Files.deleteIfExists(base.toPath());
                } catch (IOException failure) { throw new UncheckedIOException(failure); }
            }
        }
    """,
    "android/app/PendingIntent.java": """
        package android.app;
        import android.content.Context;
        import android.content.Intent;
        public class PendingIntent {
            public static final int FLAG_UPDATE_CURRENT = 0x08000000;
            public static final int FLAG_IMMUTABLE = 0x04000000;
            public final Intent intent;
            public final int requestCode;
            public final int flags;
            private PendingIntent(Intent intent, int requestCode, int flags) {
                this.intent = intent; this.requestCode = requestCode; this.flags = flags;
            }
            public static PendingIntent getActivity(Context context, int requestCode, Intent intent, int flags) {
                return new PendingIntent(intent, requestCode, flags);
            }
        }
    """,
    "android/net/Uri.java": """
        package android.net;
        public class Uri {
            private final String value;
            private Uri(String value) { this.value = value; }
            public static Uri parse(String value) { return new Uri(value); }
            public String toString() { return value; }
        }
    """,
    "android/database/Cursor.java": """
        package android.database;
        public interface Cursor {}
    """,
    "dev/galaxyxr/rootmanager/MainActivity.java": """
        package dev.galaxyxr.rootmanager;
        public class MainActivity {}
    """,
}


class AccessSecurityTests(unittest.TestCase):
    def test_production_access_store_and_provider_with_jvm_doubles(self):
        java_home = os.environ.get("JAVA_HOME")
        self.assertTrue(java_home, "Set JAVA_HOME to JDK 17 or newer to run synthetic access tests.")
        suffix = ".exe" if os.name == "nt" else ""
        javac = Path(java_home) / "bin" / f"javac{suffix}"
        java = Path(java_home) / "bin" / f"java{suffix}"
        for executable in (javac, java):
            self.assertTrue(executable.is_file(), f"Missing {executable}; set JAVA_HOME to JDK 17 or newer.")
        self.assertTrue(JSON_JAR.is_file(), f"Provide real org.json 20240303 dependency at {JSON_JAR}.")
        with tempfile.TemporaryDirectory(prefix="gxr-access-tests-") as temporary:
            root = Path(temporary)
            classes = root / "classes"
            classes.mkdir()
            sources = []
            for relative, content in STUBS.items():
                path = root / "stubs" / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")
                sources.append(str(path))
            source_root = ROOT / "app/src/dev/galaxyxr/rootmanager"
            sources.extend(str(source_root / name) for name in ("AccessStore.java", "AccessProvider.java"))
            sources.append(str(ROOT / "tests/AccessSecurityTest.java"))
            compiled = subprocess.run(
                [str(javac), "-encoding", "UTF-8", "-source", "17", "-target", "17",
                 "-cp", str(JSON_JAR), "-d", str(classes), *sources],
                capture_output=True, text=True, timeout=60, shell=False,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            executed = subprocess.run(
                [str(java), "-cp", os.pathsep.join((str(classes), str(JSON_JAR))),
                 "dev.galaxyxr.rootmanager.AccessSecurityTest", str(root / "fixtures")],
                capture_output=True, text=True, timeout=60, shell=False,
            )
            self.assertEqual(executed.returncode, 0, executed.stdout + executed.stderr)
            self.assertRegex(executed.stdout, r"Synthetic JVM access security: [1-9][0-9]+ scenarios passed")
            print(executed.stdout.strip())


if __name__ == "__main__":
    unittest.main()
