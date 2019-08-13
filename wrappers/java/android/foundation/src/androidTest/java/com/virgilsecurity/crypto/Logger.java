package com.virgilsecurity.crypto;

import android.util.Log;

public class Logger {
    public static void log(String msg) {
        Log.d("Logger", msg);
    }
    public static void log(int num) {
        Log.d("Logger", "Num:" + num);
    }
}
