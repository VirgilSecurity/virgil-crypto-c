cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

project(vscf_foundation_php)

find_package(PHP REQUIRED)

add_library(vscf_foundation_php SHARED
    vscf_foundation_php.c
)

target_include_directories(vscf_foundation_php PRIVATE
    ${PHP_INCLUDE_DIRS}
)

target_link_libraries(vscf_foundation_php
    vscf_foundation
)

set_target_properties(vscf_foundation_php PROPERTIES
    OUTPUT_NAME "vscf_foundation_php"
    PREFIX ""
    SUFFIX ".so"
)
