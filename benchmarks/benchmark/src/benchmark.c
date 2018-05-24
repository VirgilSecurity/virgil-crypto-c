/*
 * Implementation of the benchmark tool.
 */

#include "benchmark.h"

#ifndef __cplusplus
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#else
#include <cstdio>
#include <cstdlib>
#include <cstring>
using namespace std;
#endif

/**
 * Gets the current time.
 * @return The current time, in seconds.
 **/
double get_current_time();

double benchmark(void func(void *, size_t), void *data, size_t numBytes, int numBenchmarks)
{
	double mean_time = 0.0; /** The time the benchmark ran. **/
	double total_time = 0.0; /** The total time. **/
	int i;

	printf("----------------------------\nStarting benchmark...\n----------------------------\n");

	for(i = 0; i < numBenchmarks; ++i)
	{
		double start_time = 0.0; /** The time the benchmark started. **/
		double end_time = 0.0; /** The time the benchmark ended. **/
		double bench_time = 0.0; /** end_time - start_time **/

		/* Start the benchmark. */
		start_time = get_current_time();

		/* Call the function to benchmark. */
		func(data, numBytes);

		/* End the benchmark. */
		end_time = get_current_time();
		bench_time = end_time - start_time;

		/* Add the benchmark time to the total time. */
		total_time += bench_time;

		/* Add the benchmark time to mean_time and if it wasn't 0, divide by 2. */
		if(mean_time)
			mean_time = (mean_time + bench_time) / 2;
		else
			mean_time = bench_time;

		/* Print the current step. */
		printf("Completed step %d\tTime spent: %fs\n", i + 1, bench_time);
	}

	/* Gobal time spent in the benchmark. */
	printf("----------------------------\nEnded benchmark!\n");
	printf("Total time spent: %fs\n", total_time/1e9);
	printf("Mean time spent: %fns\n----------------------------\n", mean_time);

	/* Return the mean time. */
	return mean_time;
}

void benchmark2(void func1(void *, size_t), const char* description1, void func2(void *, size_t), const char* description2, void *data, size_t numBytes, int numBenchmarks)
{
	double mean_time1 = 0.0; /** The time the benchmark ran. **/
	double total_time1 = 0.0; /** The total time. **/
    double mean_time2 = 0.0; /** The time the benchmark ran. **/
    double total_time2 = 0.0; /** The total time. **/
	int i;

	printf("----------------------------\nStarting benchmark...\n----------------------------\n");

	for(i = 0; i < numBenchmarks; ++i)
	{
		double start_time1 = 0.0; /** The time the benchmark started. **/
		double end_time1 = 0.0; /** The time the benchmark ended. **/
		double bench_time1 = 0.0; /** end_time - start_time **/
		double start_time2 = 0.0; /** The time the benchmark started. **/
		double end_time2 = 0.0; /** The time the benchmark ended. **/
		double bench_time2 = 0.0; /** end_time - start_time **/
		/* Start the benchmark. */
		start_time1 = get_current_time();

		/* Call the function to benchmark. */
		func1(data, numBytes);

		/* End the benchmark. */
		end_time1 = get_current_time();
		bench_time1 = end_time1 - start_time1;

		/* Add the benchmark time to the total time. */
		total_time1 += bench_time1;

		/* Add the benchmark time to mean_time and if it wasn't 0, divide by 2. */
		if(mean_time1)
			mean_time1 = (mean_time1 + bench_time1) / 2;
		else
			mean_time1 = bench_time1;

    	/* Start the benchmark. */
    	start_time2 = get_current_time();

    	/* Call the function to benchmark. */
    	func2(data, numBytes);

    	/* End the benchmark. */
    	end_time2 = get_current_time();
    	bench_time2 = end_time2 - start_time2;

    	/* Add the benchmark time to the total time. */
    	total_time2 += bench_time2;

    	/* Add the benchmark time to mean_time and if it wasn't 0, divide by 2. */
    	if (mean_time2)
        	mean_time2 = (mean_time2 + bench_time2) / 2;
    	else
        	mean_time2 = bench_time2;
		/* Print the current step. */
		printf("Completed step %d\t%s: %fns\t%s: %fns\n", i + 1, description1, bench_time1 , description2, bench_time2 );
	}

	/* Gobal time spent in the benchmark. */
	printf("----------------------------\nEnded benchmark!\n");
	printf("Total time spent:\t%s %fs,\t %s %fs\n", description1, total_time1/1e9, description2, total_time2/1e9 );
	printf("Mean time spent:\t%s %fns,\t %s %fns\n----------------------------\n", description1, mean_time1, description2, mean_time2 );
}
/* Implement get_current_time() depending on the OS. */
#if defined(WIN32) || defined(__WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(_WIN32_)

#include <windows.h>

double get_current_time() {
	LARGE_INTENGER t, f;
	QueryPerformanceCounter(&t);
	QueryPerformanceFrequency(&f);
	return (double)t.QuadPart/(double)f.QuadPart;
}

#else

#include <sys/time.h>
#include <sys/resource.h>
#include <time.h>

double get_current_time() {
	struct timespec temp;
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &temp);
	return temp.tv_sec * 1e9 + temp.tv_nsec;
	//struct timeval t;
	//gettimeofday(&t, 0);
	//return t.tv_sec + t.tv_usec*1e-6;
}

#endif