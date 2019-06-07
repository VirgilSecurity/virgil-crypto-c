#define PICOBENCH_IMPLEMENT_WITH_MAIN
#include "picobench/picobench.hpp"

#include "unity.h"
#include "vscf_sha512.h"
#include "test_data_sha512.h"

static void sha_picobench(picobench::state& s)
{
    s.start_timer();
    for (int i = 0; i < s.iterations(); ++i) {
        vscf_sha512_t *sha512 = vscf_sha512_new();
        vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha512_DIGEST_LEN);

        vscf_sha512_start(sha512);
        vscf_sha512_update(sha512, test_sha512_VECTOR_3_INPUT);
        vscf_sha512_finish(sha512, digest);

        TEST_ASSERT_EQUAL(test_sha512_VECTOR_3_DIGEST.len, vsc_buffer_len(digest));
        TEST_ASSERT_EQUAL_HEX8_ARRAY(
                test_sha512_VECTOR_3_DIGEST.bytes, vsc_buffer_bytes(digest), vsc_buffer_len(digest));

        vsc_buffer_destroy(&digest);
        vscf_sha512_destroy(&sha512);
    }
    s.stop_timer();
}

PICOBENCH(sha_picobench);

