package dev.galaxyxr.rootmanager;

import android.app.PendingIntent;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;

public final class AccessProvider extends ContentProvider {
    private AccessStore store;

    @Override
    public boolean onCreate() {
        if (getContext() == null) return false;
        store = new AccessStore(getContext());
        return true;
    }

    @Override
    public Bundle call(String method, String arg, Bundle extras) {
        int callerUid = Binder.getCallingUid();
        if (method == null) throw new IllegalArgumentException("UNKNOWN_METHOD");
        Bundle result = new Bundle();
        result.putString("approval_scope", "diagnostic_preview");
        switch (method) {
            case "getStatus":
                result.putString("status", "diagnostic_only");
                result.putBoolean("root_available", false);
                result.putBoolean("boot_restore_enabled", false);
                return result;
            case "requestAccess":
                String requestId = store.recordRequest(callerUid);
                Intent review = new Intent(getContext(), MainActivity.class);
                review.setAction("dev.galaxyxr.rootmanager.REVIEW_ACCESS");
                review.setData(Uri.parse("content://dev.galaxyxr.rootmanager.access/requests/" + requestId));
                review.putExtra("request_id", requestId);
                PendingIntent approval = PendingIntent.getActivity(getContext(), 0, review,
                        PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
                result.putString("request_id", requestId);
                result.putParcelable("approval_intent", approval);
                return result;
            case "getAccess":
                result.putString("decision", store.status(callerUid));
                return result;
            case "execute":
                result.putString("error", "ROOT_BACKEND_UNAVAILABLE");
                return result;
            default:
                throw new IllegalArgumentException("UNKNOWN_METHOD");
        }
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
            String[] selectionArgs, String sortOrder) {
        throw new UnsupportedOperationException("CALL_ONLY");
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        throw new UnsupportedOperationException("CALL_ONLY");
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException("CALL_ONLY");
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException("CALL_ONLY");
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) {
        throw new UnsupportedOperationException("CALL_ONLY");
    }

    @Override
    public String getType(Uri uri) {
        return null;
    }
}
