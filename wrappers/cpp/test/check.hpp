// Minimal dependency-free test harness for the C++ SDK round-trip tests.
// Each test executable is a single translation unit, so the inline failure
// counter has one definition per program. Tests must build under -fno-exceptions,
// so we never throw — a failed CHECK records and continues.
#pragma once

#include <cstdio>
#include <cstdint>
#include <vector>

namespace vsctest {
inline int failures = 0;
}

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);        \
            ++vsctest::failures;                                               \
        }                                                                      \
    } while (0)

#define TEST_MAIN_RETURN()                                                     \
    do {                                                                       \
        if (vsctest::failures) {                                               \
            std::printf("%d check(s) failed\n", vsctest::failures);            \
            return 1;                                                          \
        }                                                                      \
        std::printf("all checks passed\n");                                    \
        return 0;                                                              \
    } while (0)
