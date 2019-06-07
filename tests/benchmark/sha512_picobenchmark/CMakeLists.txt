cmake_minimum_required(VERSION 3.11)
project(sha512_picobenchmark CXX)

add_executable(sha512_picobenchmark
        src/main.cpp
        )

target_link_directories(sha512_picobenchmark
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}../picobenchmark/include/picobenchmark>
        )

target_link_libraries(sha512_picobenchmark test_utils test_data_foundation vsc::foundation picobench)
