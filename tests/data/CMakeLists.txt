project (test_data C)

FILE(GLOB SRCFILES "src/*.c")
FILE(GLOB HDRFILES "include/*.h")

add_library(test_data STATIC ${HDRFILES} ${SRCFILES})

target_include_directories(test_data
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
    PUBLIC $<INSTALL_INTERFACE:include>
)
