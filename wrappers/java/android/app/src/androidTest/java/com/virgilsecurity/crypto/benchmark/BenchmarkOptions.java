package com.virgilsecurity.crypto.benchmark;

import android.util.Log;
import com.virgilsecurity.crypto.test.BuildConfig;

public class BenchmarkOptions {

  public static final String TAG = "Benchmark";
  public static final int MEASUREMENTS;

  static {
    MEASUREMENTS = BuildConfig.BENCHMARK_MEASUREMENTS;
    Log.i(TAG, MEASUREMENTS + " measurement(s)");
  }

}
