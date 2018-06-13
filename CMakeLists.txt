#   Copyright (C) 2015-2018 Virgil Security Inc.
#
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are
#   met:
#
#       (1) Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#
#       (2) Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#
#       (3) Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
#   IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#   DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
#   INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
#   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
#   STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
#   IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#   POSSIBILITY OF SUCH DAMAGE.
#
#   Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

cmake_minimum_required(VERSION 3.11 FATAL_ERROR)

project(virgil-crypto-c-top VERSION 0.1.0 LANGUAGES C)

# ---------------------------------------------------------------------------
#   Add helper modules
# ---------------------------------------------------------------------------
include("cmake/clangformat.cmake")
include("GNUInstallDirs")


# ---------------------------------------------------------------------------
#   Options
# ---------------------------------------------------------------------------
option(ENABLE_TESTING "On/Off library integration tests." ON)
option(ENABLE_BENCHMARKS "On/Off build library benchmarks." ON)


# ---------------------------------------------------------------------------
#   Dependencies / thirdparty libraries
# ---------------------------------------------------------------------------

#
# MbedTLS
#
add_subdirectory ("thirdparty/mbedtls")

#
# Pythia
#
add_subdirectory ("thirdparty/pythia")

#
# Library that force compiler to the pedantic mode.
#
add_library(enable_pedantic INTERFACE)
target_compile_options(enable_pedantic
        INTERFACE
        $<$<C_COMPILER_ID:GNU>:-Wall -Werror -pedantic>
        $<$<OR:$<C_COMPILER_ID:Clang>,$<C_COMPILER_ID:AppleClang>>:-Werror -Wall -pedantic -Wassign-enum>
        )

#
# Library that force compiler to the profiling mode.
#
add_library(enable_profiling INTERFACE)
target_compile_options(enable_profiling INTERFACE $<$<C_COMPILER_ID:GNU>:-pg>)
target_link_libraries(enable_profiling INTERFACE $<$<C_COMPILER_ID:GNU>:-pg>)


# ---------------------------------------------------------------------------
#   Library core libraries
# ---------------------------------------------------------------------------
add_subdirectory ("library/common")
add_subdirectory ("library/foundation")
add_subdirectory ("library/pythia")


# ---------------------------------------------------------------------------
#   Integration tests
# ---------------------------------------------------------------------------
if(ENABLE_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()


# ---------------------------------------------------------------------------
#   Integration tests
# ---------------------------------------------------------------------------
if(ENABLE_BENCHMARKS)
    add_subdirectory(benchmarks)
endif()

# ---------------------------------------------------------------------------
#   Show code stats
# ---------------------------------------------------------------------------
find_program (CLOC_EXE cloc)

if(CLOC_EXE)
    add_custom_target(cloc-common
        COMMAND ${CLOC_EXE}
                "${CMAKE_CURRENT_LIST_DIR}/library/common/include/virgil"
                "${CMAKE_CURRENT_LIST_DIR}/library/common/include/virgil/private"
                "${CMAKE_CURRENT_LIST_DIR}/library/common/src"
        COMMENT "Calculate lines of the 'common' library..."
    )

    add_custom_target(cloc-foundation
        COMMAND ${CLOC_EXE}
                "${CMAKE_CURRENT_LIST_DIR}/library/foundation/include/virgil"
                "${CMAKE_CURRENT_LIST_DIR}/library/foundation/include/virgil/private"
                "${CMAKE_CURRENT_LIST_DIR}/library/foundation/src"
        COMMENT "Calculate lines of the 'foundation' library..."
    )

    add_custom_target(cloc-pythia
        COMMAND ${CLOC_EXE}
                "${CMAKE_CURRENT_LIST_DIR}/library/pythia/include/virgil"
                "${CMAKE_CURRENT_LIST_DIR}/library/pythia/include/virgil/private"
                "${CMAKE_CURRENT_LIST_DIR}/library/pythia/src"
        COMMENT "Calculate lines of the 'pythia' library..."
    )

    add_custom_target(cloc)
    add_dependencies(cloc cloc-common cloc-foundation cloc-pythia)
endif()
