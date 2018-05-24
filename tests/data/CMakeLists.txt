cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

project(test_data VERSION 0.1.0 LANGUAGES C)

add_library(test_data "")
target_sources(test_data
        PUBLIC
        "${CMAKE_CURRENT_LIST_DIR}/include/test_data_aes_256_gcm.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/test_data_kdf1.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/test_data_sha224.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/test_data_sha256.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/test_data_sha384.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/test_data_sha512.h"
        "${CMAKE_CURRENT_LIST_DIR}/include/test_data_types.h"

        PRIVATE
        "${CMAKE_CURRENT_LIST_DIR}/src/test_data_aes_256_gcm.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/test_data_kdf1.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/test_data_sha224.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/test_data_sha256.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/test_data_sha384.c"
        "${CMAKE_CURRENT_LIST_DIR}/src/test_data_sha512.c"
        )

target_include_directories(test_data
        PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
        )
