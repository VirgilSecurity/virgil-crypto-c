cmake_minimum_required(VERSION 3.11 FATAL_ERROR)

if (NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    # not using regular Clang or AppleClang

    message("Error. Use Clang for fuzzy testing.")
endif()

macro(_add_test test)
    add_executable(${test} src/${test}.c)
    set_target_properties(${test} PROPERTIES C_STANDARD "99")
    set_target_properties(${test} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${test})
    add_test (NAME ${test} COMMAND ${test})

    target_compile_options(${test}
            PRIVATE
            $<$<C_COMPILER_ID:Clang>: -Wall -Werror -g -O1 -fsanitize=fuzzer,address -fno-omit-frame-pointer>
            $<$<C_COMPILER_ID:AppleClang>: -Wall -Werror -g -O1 -fsanitize=fuzzer,address -fno-omit-frame-pointer>
            )

    target_add_filename_definitions(${test})
    target_compile_definitions(${test} PRIVATE "ENABLE_HEAVY_TESTS=$<BOOL:${ENABLE_HEAVY_TESTS}>")
    target_link_libraries(${test}
            test_utils
            test_data_foundation
            vsc::foundation
            $<$<C_COMPILER_ID:Clang>:-fsanitize=fuzzer,address>
            $<$<C_COMPILER_ID:AppleClang>:-fsanitize=fuzzer,address>
            )

    if(COMMAND add_clangformat)
        add_clangformat(${test})
    endif()
endmacro()

_add_test(pkcs8_test_fuzzy)

