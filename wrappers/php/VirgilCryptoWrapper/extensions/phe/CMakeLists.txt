cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

project(virgil_crypto_phe_php VERSION ${virgil_crypto_php_VERSION} LANGUAGES C)

if(NOT VIRGIL_LIB_PHE)
    message(STATUS "Skip building the PHP wrapper for library 'phe', which is not built.")
    return()
endif()

add_library(phe_php SHARED)

set_target_properties(phe_php PROPERTIES
    OUTPUT_NAME "vsce_phe_php"
    PREFIX ""
    SUFFIX ".so"
)

if(WIN32)
    set_target_properties(phe_php PROPERTIES SUFFIX ".dll")
endif()

target_compile_definitions(phe_php
    PRIVATE
        VSCE_PHP_SHARED_LIBRARY
        VSCE_PHP_INTERNAL_BUILD=1
)

target_sources(phe_php
    PRIVATE
        $<BUILD_INTERFACE:vsce_phe_php.c>
)

target_include_directories(phe_php
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>
    PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/../foundation>
)

target_link_libraries(phe_php
    PUBLIC
        vsc::phe
    PRIVATE
        phplib
        "$<$<STREQUAL:${CMAKE_SYSTEM_NAME},Darwin>:-undefined dynamic_lookup>"
        $<$<BOOL:${WIN32}>:foundation_php>
)

if(VIRGIL_INSTALL_WRAP_LIBS)
    install(TARGETS phe_php
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
endif()
