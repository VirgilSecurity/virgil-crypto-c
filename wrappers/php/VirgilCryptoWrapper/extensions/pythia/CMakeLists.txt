cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

project(vscp_pythia_php)

find_package(PHP REQUIRED)

add_library(vscp_pythia_php SHARED
    vscp_pythia_php.c
)

target_include_directories(vscp_pythia_php PRIVATE
    ${PHP_INCLUDE_DIRS}
)

target_link_libraries(vscp_pythia_php
    vscp_pythia
)

set_target_properties(vscp_pythia_php PROPERTIES
    OUTPUT_NAME "vscp_pythia_php"
    PREFIX ""
    SUFFIX ".so"
)
