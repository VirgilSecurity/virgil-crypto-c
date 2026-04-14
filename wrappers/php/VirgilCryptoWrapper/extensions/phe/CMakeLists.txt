cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

project(vsce_phe_php)

find_package(PHP REQUIRED)

add_library(vsce_phe_php SHARED
    vsce_phe_php.c
)

target_include_directories(vsce_phe_php PRIVATE
    ${PHP_INCLUDE_DIRS}
)

target_link_libraries(vsce_phe_php
    vsce_phe
)

set_target_properties(vsce_phe_php PROPERTIES
    OUTPUT_NAME "vsce_phe_php"
    PREFIX ""
    SUFFIX ".so"
)
