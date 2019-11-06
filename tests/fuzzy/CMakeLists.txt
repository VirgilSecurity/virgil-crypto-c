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
            $<$<C_COMPILER_ID:Clang>: -Wall -Werror -g -O0  -fsanitize=address -fsanitize=fuzzer>
            )

    # enable_target_asan(${test})

    target_add_filename_definitions(${test})
    target_link_libraries(${test}
            PRIVATE
            test_utils
            test_data_foundation
            vsc::foundation
            $<$<C_COMPILER_ID:Clang>:-fsanitize=address,fuzzer>
            )

    if(COMMAND add_clangformat)
        add_clangformat(${test})
    endif()
endmacro()

_add_test(key_asn1_deserializer_fuzzy)
_add_test(key_provider_test_fuzzy)

