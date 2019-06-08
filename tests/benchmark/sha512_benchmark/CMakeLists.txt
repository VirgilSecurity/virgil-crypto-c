cmake_minimum_required(VERSION 3.11)
project(sha512_benchmark CXX)

add_executable(sha512_benchmark
        src/main.cpp
        )
target_link_directories(sha512_benchmark
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}../benchmark/include/benchmark>
        )

target_link_libraries(sha512_benchmark test_utils test_data_foundation vsc::foundation benchmark_framework)
