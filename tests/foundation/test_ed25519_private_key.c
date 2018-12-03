#include "unity.h"
#include "test_utils.h"


#define TEST_DEPENDENCIES_AVAILABLE (VSCF_ED25519_PRIVATE_KEY && VSCF_FAKE_RANDOM && VSCF_RANDOM && VSCF_ENDIANNESS)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_assert.h"

#include "vscf_export_public_key.h"
#include "vscf_ed25519_private_key.h"
#include "vscf_ed25519_public_key.h"
#include "vscf_random.h"
#include "vscf_fake_random.h"

#include "test_data_ed25519.h"

void
test__ed25519_private_key_key_len__imported_PRIVATE_KEY__returns_32(void) {
    vscf_ed25519_private_key_impl_t *private_key_impl = vscf_ed25519_private_key_new();

    vscf_error_t result = vscf_ed25519_private_key_import_private_key(private_key_impl, test_ed25519_PRIVATE_KEY);
    VSCF_ASSERT(result == vscf_SUCCESS);
    TEST_ASSERT_EQUAL(32, vscf_ed25519_private_key_key_len(private_key_impl));
    vscf_ed25519_private_key_destroy(&private_key_impl);
}

void
test__ed25519_private_key_export_private_key__from_imported_PRIVATE_KEY__expected_equal(void) {
    vscf_ed25519_private_key_impl_t *private_key_impl = vscf_ed25519_private_key_new();
    vscf_error_t result = vscf_ed25519_private_key_import_private_key(private_key_impl, test_ed25519_PRIVATE_KEY);
    VSCF_ASSERT(result == vscf_SUCCESS);

    vsc_buffer_t *exported_key_buf =
            vsc_buffer_new_with_capacity(vscf_ed25519_private_key_exported_private_key_len(private_key_impl));
    result = vscf_ed25519_private_key_export_private_key(private_key_impl, exported_key_buf);

    TEST_ASSERT_EQUAL(vscf_SUCCESS, result);
    TEST_ASSERT_EQUAL(test_ed25519_PRIVATE_KEY.len, vsc_buffer_len(exported_key_buf));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(
            test_ed25519_PRIVATE_KEY.bytes, vsc_buffer_bytes(exported_key_buf), vsc_buffer_len(exported_key_buf));

    vsc_buffer_destroy(&exported_key_buf);
    vscf_ed25519_private_key_destroy(&private_key_impl);
}

void
test__ed25519_private_key_extract_public_key__from_imported_PRIVATE_KEY__when_exported_equals_PUBLIC_KEY(void) {
    //  Setup dependencies
    vscf_ed25519_private_key_impl_t *private_key_impl = vscf_ed25519_private_key_new();

    //  Import private key
    // vscf_error_t result = vscf_ed25519_private_key_import_private_key(private_key_impl, test_ed25519_PRIVATE_KEY);
    vscf_error_t result =
            vscf_ed25519_private_key_import_private_key(private_key_impl, test_ed25519_PRIVATE_KEY_REVERSE);
    VSCF_ASSERT(result == vscf_SUCCESS);

    //  Extract public key
    vscf_ed25519_public_key_impl_t *public_key_impl = vscf_ed25519_private_key_extract_public_key(private_key_impl);
    TEST_ASSERT_NOT_NULL(public_key_impl);

    vsc_buffer_t *exported_key_buf =
            vsc_buffer_new_with_capacity(vscf_export_public_key_exported_public_key_len(public_key_impl));

    vscf_error_t export_err = vscf_export_public_key(public_key_impl, exported_key_buf);
    VSCF_ASSERT(export_err == vscf_SUCCESS);

    //  Check

    TEST_ASSERT_EQUAL(test_ed25519_PUBLIC_KEY.len, vsc_buffer_len(exported_key_buf));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(
            test_ed25519_PUBLIC_KEY.bytes, vsc_buffer_bytes(exported_key_buf), vsc_buffer_len(exported_key_buf));

    vscf_ed25519_private_key_destroy(&private_key_impl);
    vscf_impl_destroy(&public_key_impl);
    vsc_buffer_destroy(&exported_key_buf);
}

void
test__ed25519_private_key_sign__with_imported_PRIVATE_KEY_and_MESSAGE__equals_MESSAGE_SIGNATURE(void) {

    //  Setup dependencies
    vscf_ed25519_private_key_impl_t *private_key_impl = vscf_ed25519_private_key_new();

    //  Import private key
    vscf_error_t result = vscf_ed25519_private_key_import_private_key(private_key_impl, test_ed25519_PRIVATE_KEY);
    VSCF_ASSERT(result == vscf_SUCCESS);

    //  Sign
    vsc_buffer_t *signature = vsc_buffer_new_with_capacity(vscf_ed25519_private_key_signature_len(private_key_impl));
    vscf_error_t sign_result = vscf_ed25519_private_key_sign(private_key_impl, test_ed25519_MESSAGE, signature);

    //  Check
    TEST_ASSERT_EQUAL(vscf_SUCCESS, sign_result);
    TEST_ASSERT_EQUAL(test_ed25519_SIGNATURE.len, vsc_buffer_len(signature));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_ed25519_SIGNATURE.bytes, vsc_buffer_bytes(signature), vsc_buffer_len(signature));

    //  Cleanup
    vsc_buffer_destroy(&signature);
    vscf_ed25519_private_key_destroy(&private_key_impl);
}

void
test__ed25519_private_key_export_private_key_with_imported_ed25519_PRIVATE_KEY__when_exported_equals_ed25519_PRIVATE_KEY(
        void) {
    //  Setup dependencies
    vscf_ed25519_private_key_impl_t *private_key_impl = vscf_ed25519_private_key_new();

    //  Import private key
    vscf_error_t result = vscf_ed25519_private_key_import_private_key(private_key_impl, test_ed25519_PRIVATE_KEY);
    VSCF_ASSERT(result == vscf_SUCCESS);

    vsc_buffer_t *exported_key_buf =
            vsc_buffer_new_with_capacity(vscf_ed25519_private_key_exported_private_key_len(private_key_impl));

    vscf_error_t export_err = vscf_export_private_key(private_key_impl, exported_key_buf);
    VSCF_ASSERT(export_err == vscf_SUCCESS);

    // Check
    TEST_ASSERT_EQUAL(test_ed25519_PRIVATE_KEY.len, vsc_buffer_len(exported_key_buf));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_ed25519_PRIVATE_KEY_REVERSE.bytes, vsc_buffer_bytes(exported_key_buf),
            vsc_buffer_len(exported_key_buf));
    vscf_ed25519_private_key_destroy(&private_key_impl);
    vsc_buffer_destroy(&exported_key_buf);
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
    RUN_TEST(test__ed25519_private_key_key_len__imported_PRIVATE_KEY__returns_32);
    RUN_TEST(test__ed25519_private_key_export_private_key__from_imported_PRIVATE_KEY__expected_equal);
    RUN_TEST(test__ed25519_private_key_extract_public_key__from_imported_PRIVATE_KEY__when_exported_equals_PUBLIC_KEY);
    RUN_TEST(test__ed25519_private_key_sign__with_imported_PRIVATE_KEY_and_MESSAGE__equals_MESSAGE_SIGNATURE);
    RUN_TEST(test__ed25519_private_key_export_private_key_with_imported_ed25519_PRIVATE_KEY__when_exported_equals_ed25519_PRIVATE_KEY);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
