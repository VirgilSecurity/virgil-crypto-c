cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

project(virgil_crypto_pythia_php VERSION ${virgil_crypto_php_VERSION} LANGUAGES C)

if(NOT VIRGIL_LIB_PYTHIA)
    message(STATUS "Skip building the PHP wrapper for library 'pythia', which is not built.")
    return()
endif()

add_library(pythia_php SHARED)

set_target_properties(pythia_php PROPERTIES
    OUTPUT_NAME "vscp_pythia_php"
    PREFIX ""
    SUFFIX ".so"
)

if(WIN32)
    set_target_properties(pythia_php PROPERTIES SUFFIX ".dll")
endif()

target_compile_definitions(pythia_php
    PRIVATE
        VSCP_PHP_SHARED_LIBRARY
        VSCP_PHP_INTERNAL_BUILD=1
)

target_sources(pythia_php
    PRIVATE
        $<BUILD_INTERFACE:vscp_pythia_php.c>
)

target_include_directories(pythia_php
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>
)

target_link_libraries(pythia_php
    PUBLIC
        vsc::pythia
    PRIVATE
        phplib
        "$<$<STREQUAL:${CMAKE_SYSTEM_NAME},Darwin>:-undefined dynamic_lookup>"
)

if(VIRGIL_INSTALL_WRAP_LIBS)
    install(TARGETS pythia_php
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
endif()
