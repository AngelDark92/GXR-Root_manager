package dev.galaxyxr.rootmanager;

import android.content.Context;
import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;
import android.os.Build;
import android.util.Log;

import java.util.ArrayList;
import java.util.List;

/**
 * Finds the wireless-debugging connect port over mDNS (_adb-tls-connect._tcp)
 * and, while the pairing dialog is open, the pairing port
 * (_adb-tls-pairing._tcp). Pairing needs the 6-digit code shown in Developer
 * options. The port rotates every time the wireless-debugging toggle is cycled,
 * so this runs on every connect attempt instead of trusting a stored port.
 */
public final class PortDiscovery {
    public interface Log {
        void line(String text);
    }

    private PortDiscovery() {}

    /** Scans for up to timeoutMs; returns candidate ports, best first. */
    public static List<Integer> discoverPorts(Context context, long timeoutMs, Log log) {
        return discover(context, timeoutMs, log, "_adb-tls-connect._tcp");
    }

    public static List<Integer> discoverPairingPorts(Context context, long timeoutMs, Log log) {
        return discover(context, timeoutMs, log, "_adb-tls-pairing._tcp");
    }

    private static List<Integer> discover(Context context, long timeoutMs, Log log, String serviceType) {
        NsdManager nsd = (NsdManager) context.getSystemService(Context.NSD_SERVICE);
        List<Integer> ports = new ArrayList<>();
        if (nsd == null) {
            log.line("[!] NSD service unavailable");
            return ports;
        }
        final Object done = new Object();
        final List<NsdServiceInfo> found = new ArrayList<>();
        NsdManager.DiscoveryListener listener = new NsdManager.DiscoveryListener() {
            @Override public void onDiscoveryStarted(String serviceType) {}
            @Override public void onServiceLost(NsdServiceInfo serviceInfo) {}
            @Override public void onDiscoveryStopped(String serviceType) {}
            @Override public void onStartDiscoveryFailed(String serviceType, int errorCode) {
                synchronized (done) { done.notifyAll(); }
            }
            @Override public void onStopDiscoveryFailed(String serviceType, int errorCode) {}
            @Override public void onServiceFound(NsdServiceInfo serviceInfo) {
                found.add(serviceInfo);
                synchronized (done) { done.notifyAll(); }
            }
        };
        try {
            nsd.discoverServices(serviceType, NsdManager.PROTOCOL_DNS_SD, listener);
        } catch (IllegalArgumentException failure) {
            log.line("[!] mDNS discovery rejected: " + failure.getMessage());
            return ports;
        }
        long deadline = System.currentTimeMillis() + timeoutMs;
        try {
            synchronized (done) {
                while (System.currentTimeMillis() < deadline && found.isEmpty()) {
                    done.wait(500);
                }
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
        // Resolve every candidate; stale advertisements are filtered later by
        // the connect loop (they refuse instantly).
        long resolveDeadline = System.currentTimeMillis() + 10000;
        while (System.currentTimeMillis() < resolveDeadline) {
            NsdServiceInfo candidate = null;
            synchronized (found) {
                if (!found.isEmpty()) candidate = found.remove(0);
            }
            if (candidate == null) {
                boolean pending;
                synchronized (found) { pending = !found.isEmpty(); }
                if (!pending) {
                    try { Thread.sleep(400); } catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
                    synchronized (found) { if (found.isEmpty()) break; }
                    continue;
                }
                continue;
            }
            int resolved = resolveOne(nsd, candidate, resolveDeadline);
            if (resolved > 0 && !ports.contains(resolved)) {
                log.line("    mDNS candidate port: " + resolved);
                ports.add(resolved);
            }
        }
        try { nsd.stopServiceDiscovery(listener); } catch (IllegalArgumentException ignored) {}
        if (ports.isEmpty()) {
            log.line("[!] no mDNS service found; wireless debugging toggle may be off");
        }
        return ports;
    }

    /** Backward-compatible single-port scan. */
    public static int discover(Context context, long timeoutMs, Log log) {
        List<Integer> ports = discoverPorts(context, timeoutMs, log);
        return ports.isEmpty() ? -1 : ports.get(0);
    }

    private static int resolveOne(NsdManager nsd, NsdServiceInfo service, long deadline) {
        final Object resolved = new Object();
        final int[] portHolder = {-1};
        NsdManager.ResolveListener listener = new NsdManager.ResolveListener() {
            @Override public void onResolveFailed(NsdServiceInfo serviceInfo, int errorCode) {
                synchronized (resolved) { resolved.notifyAll(); }
            }
            @Override public void onServiceResolved(NsdServiceInfo serviceInfo) {
                portHolder[0] = serviceInfo.getPort();
                synchronized (resolved) { resolved.notifyAll(); }
            }
        };
        try {
            nsd.resolveService(service, listener);
            synchronized (resolved) {
                while (portHolder[0] < 0 && System.currentTimeMillis() < deadline) {
                    resolved.wait(500);
                }
            }
        } catch (IllegalArgumentException | InterruptedException failure) {
            return -1;
        }
        return portHolder[0];
    }

    /** True when wireless debugging is enabled according to the framework. */
    public static boolean wirelessEnabled(Context context) {
        if (Build.VERSION.SDK_INT < 30) return false;
        try {
            int value = android.provider.Settings.Global.getInt(
                context.getContentResolver(), "adb_wifi_enabled", 0);
            return value == 1;
        } catch (Exception failure) {
            return false;
        }
    }
}