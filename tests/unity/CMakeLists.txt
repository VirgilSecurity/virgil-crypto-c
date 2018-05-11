project (unity C)

add_library(unity STATIC
    "${CMAKE_CURRENT_LIST_DIR}/include/unity.h"
    "${CMAKE_CURRENT_LIST_DIR}/include/unity_internals.h"
    "${CMAKE_CURRENT_LIST_DIR}/src/unity.c"
)

target_include_directories(unity
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
    PUBLIC $<INSTALL_INTERFACE:include>
)
