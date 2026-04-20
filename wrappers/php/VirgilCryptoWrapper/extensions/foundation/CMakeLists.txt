cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

project(virgil_crypto_foundation_php VERSION ${virgil_crypto_php_VERSION} LANGUAGES C)

if(NOT VIRGIL_LIB_FOUNDATION)
    message(STATUS "Skip building the PHP wrapper for library 'foundation', which is not built.")
    return()
endif()

add_library(foundation_php SHARED)

set_target_properties(foundation_php PROPERTIES
    OUTPUT_NAME "vscf_foundation_php"
    PREFIX ""
    SUFFIX ".so"
)

if(WIN32)
    set_target_properties(foundation_php PROPERTIES SUFFIX ".dll")
endif()

target_compile_definitions(foundation_php
    PRIVATE
        VSCF_PHP_SHARED_LIBRARY
        VSCF_PHP_INTERNAL_BUILD=1
)

target_sources(foundation_php
    PRIVATE
        $<BUILD_INTERFACE:vscf_foundation_php.c>
)

target_include_directories(foundation_php
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>
)

target_link_libraries(foundation_php
    PUBLIC
        vsc::foundation
    PRIVATE
        phplib
        "$<$<STREQUAL:${CMAKE_SYSTEM_NAME},Darwin>:-undefined dynamic_lookup>"
)

if(VIRGIL_INSTALL_WRAP_LIBS)
    install(TARGETS foundation_php
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
endif()
