cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

project(benchmark_data VERSION 0.1.0 LANGUAGES C)

add_library(benchmark_data "")
target_sources(benchmark_data
        PUBLIC
        "${CMAKE_CURRENT_LIST_DIR}/include/bench_data_kdf1.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/bench_data_kdf2.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/bench_data_sha224.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/bench_data_sha256.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/bench_data_sha384.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/bench_data_sha512.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/bench_data_types.h"

        PRIVATE
        "${CMAKE_CURRENT_LIST_DIR}/src/bench_data_kdf1.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/bench_data_kdf2.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/bench_data_sha224.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/bench_data_sha256.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/bench_data_sha384.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/bench_data_sha512.c"
        )

target_include_directories(benchmark_data
        PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
        )
