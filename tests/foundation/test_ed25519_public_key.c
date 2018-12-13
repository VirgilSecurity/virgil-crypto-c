#include "unity.h"
#include "test_utils.h"


#define TEST_DEPENDENCIES_AVAILABLE (VSCF_ED25519_PUBLIC_KEY && VSCF_FAKE_RANDOM && VSCF_RANDOM && VSCF_ENDIANNESS)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_assert.h"

#include "vscf_ed25519_public_key.h"
#include "vscf_random.h"
#include "vscf_fake_random.h"

#include "test_data_ed25519.h"


// --------------------------------------------------------------------------
//  Should have it to prevent linkage erros in MSVC.
// --------------------------------------------------------------------------
// clang-format off
void setUp(void) { }
void tearDown(void) { }
void suiteSetUp(void) { }
int suiteTearDown(int num_failures) { return num_failures; }
// clang-format on


// --------------------------------------------------------------------------
//  Test functions.
// --------------------------------------------------------------------------
void
test__ed25519_public_key_key_len__imported_PUBLIC_KEY__returns_32(void) {
    vscf_ed25519_public_key_impl_t *public_key_impl = vscf_ed25519_public_key_new();
    vscf_error_t result = vscf_ed25519_public_key_import_public_key(public_key_impl, test_ed25519_PUBLIC_KEY);
    VSCF_ASSERT(result == vscf_SUCCESS);
    TEST_ASSERT_EQUAL(32, vscf_ed25519_public_key_key_len(public_key_impl));
    vscf_ed25519_public_key_destroy(&public_key_impl);
}

void
test__ed25519_public_key_export_public_key__from_imported_PUBLIC_KEY__expected_equal(void) {
    vscf_ed25519_public_key_impl_t *public_key_impl = vscf_ed25519_public_key_new();
    vscf_error_t result = vscf_ed25519_public_key_import_public_key(public_key_impl, test_ed25519_PUBLIC_KEY);
    VSCF_ASSERT(result == vscf_SUCCESS);
    vsc_buffer_t *exported_key_buf =
            vsc_buffer_new_with_capacity(vscf_ed25519_public_key_exported_public_key_len(public_key_impl));
    result = vscf_ed25519_public_key_export_public_key(public_key_impl, exported_key_buf);
    TEST_ASSERT_EQUAL(vscf_SUCCESS, result);
    TEST_ASSERT_EQUAL(test_ed25519_PUBLIC_KEY.len, vsc_buffer_len(exported_key_buf));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(
            test_ed25519_PUBLIC_KEY.bytes, vsc_buffer_bytes(exported_key_buf), vsc_buffer_len(exported_key_buf));
    vsc_buffer_destroy(&exported_key_buf);
    vscf_ed25519_public_key_destroy(&public_key_impl);
}

void
test__ed25519_public_key_verify__with_imported_PUBLIC_KEY_and_DATA_SIGNATURE(void) {
    vscf_ed25519_public_key_impl_t *public_key_impl = vscf_ed25519_public_key_new();
    vscf_error_t result = vscf_ed25519_public_key_import_public_key(public_key_impl, test_ed25519_PUBLIC_KEY_REVERSE);
    VSCF_ASSERT(result == vscf_SUCCESS);
    bool verify_result = vscf_ed25519_public_key_verify(public_key_impl, test_ed25519_MESSAGE, test_ed25519_SIGNATURE);
    //  Check
    TEST_ASSERT_EQUAL(true, verify_result);

    //  Cleanup
    vscf_ed25519_public_key_destroy(&public_key_impl);
}


#endif // TEST_DEPENDENCIES_AVAILABLE

// --------------------------------------------------------------------------
// Entrypoint.
// clang-format off
// --------------------------------------------------------------------------

int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__ed25519_public_key_key_len__imported_PUBLIC_KEY__returns_32);
    RUN_TEST(test__ed25519_public_key_export_public_key__from_imported_PUBLIC_KEY__expected_equal);
    RUN_TEST(test__ed25519_public_key_verify__with_imported_PUBLIC_KEY_and_DATA_SIGNATURE);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
