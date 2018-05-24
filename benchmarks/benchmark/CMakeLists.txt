project (benchmark C)

add_library(benchmark STATIC
    "${CMAKE_CURRENT_LIST_DIR}/include/benchmark.h"
    "${CMAKE_CURRENT_LIST_DIR}/src/benchmark.c"
)

target_include_directories(benchmark
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
    PUBLIC $<INSTALL_INTERFACE:include>
)
