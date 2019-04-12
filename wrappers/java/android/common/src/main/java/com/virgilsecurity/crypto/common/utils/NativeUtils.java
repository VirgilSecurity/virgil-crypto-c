package com.virgilsecurity.crypto.common.utils;

import android.util.Log;

public class NativeUtils {
	private static final String TAG = "NativeUtils";

	public static void load(String name) {
		try {
			Log.d(TAG, "Loading library: " + name);
			System.loadLibrary(name);
		} catch (Exception e) {
			Log.e(TAG, "Native library can't be loaded.", e);
		}
	}

	/**
	 * Private constructor - this class will never be instanced
	 */
	private NativeUtils() {
	}

}
