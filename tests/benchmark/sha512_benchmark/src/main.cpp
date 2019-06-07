#include "benchmark/benchmark.h"

#include "unity.h"
#include "vscf_sha512.h"
#include "test_data_sha512.h"

static void sha512_bench (benchmark::State & state)
{
    while (state.KeepRunning () ) {
        vscf_sha512_t *sha512 = vscf_sha512_new();
        vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha512_DIGEST_LEN);

        vscf_sha512_start(sha512);
        vscf_sha512_update(sha512, test_sha512_VECTOR_3_INPUT);
        vscf_sha512_finish(sha512, digest);

        TEST_ASSERT_EQUAL(test_sha512_VECTOR_3_DIGEST.len, vsc_buffer_len(digest));
        TEST_ASSERT_EQUAL_HEX8_ARRAY(test_sha512_VECTOR_3_DIGEST.bytes, vsc_buffer_bytes(digest), vsc_buffer_len(digest));

        vsc_buffer_destroy(&digest);
        vscf_sha512_destroy(&sha512);
    }
}
BENCHMARK (sha512_bench);

int main (int argc, const char ** argv) {
    benchmark::Initialize(&argc, (char**)argv);
    benchmark::RunSpecifiedBenchmarks();
    return 0;
}