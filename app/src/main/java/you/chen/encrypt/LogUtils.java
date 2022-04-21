package you.chen.encrypt;

import android.util.Log;

public final class LogUtils {

    private LogUtils() {}

    private static final String TAG = "youxiaochen";

    public static void i(String msg) {
        Log.i(TAG, msg);
    }

    public static void i(String format, Object ...args) {
        Log.i(TAG, String.format(format, args));
    }
}
