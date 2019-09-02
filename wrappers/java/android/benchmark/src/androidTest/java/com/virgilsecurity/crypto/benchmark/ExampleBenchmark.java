package com.virgilsecurity.crypto.benchmark;

import android.util.Log;

import androidx.benchmark.BenchmarkRule;
import androidx.benchmark.BenchmarkState;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Benchmark, which will execute on an Android device.
 * <p>
 * The while loop will measure the contents of the loop, and Studio will
 * output the result. Modify your code to see how it affects performance.
 */
@RunWith(AndroidJUnit4.class)
public class ExampleBenchmark {

  @Rule
  public BenchmarkRule mBenchmarkRule = new BenchmarkRule();

  @Test
  public void log() {
    final BenchmarkState state = mBenchmarkRule.getState();
    while (state.keepRunning()) {
      Log.d("LogBenchmark", "the cost of writing this log method will be measured");
    }
  }
}
