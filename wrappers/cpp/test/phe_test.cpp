// C++ SDK round-trip test for the phe library. setup_defaults() wires up phe's
// foundation-backed dependencies (a foundation CtrDrbg random), so the cross-project
// link is exercised at runtime; set_random is an alternative to setup_defaults (the C
// API asserts the dependency is unset), so the two are not combined here.
#include <virgil/crypto/phe/phe_cipher.hpp>
#include <virgil/crypto/phe/phe_common.hpp>

#include "check.hpp"

namespace p = virgil::crypto::phe;

// PheCipher encrypt -> decrypt round-trips under a fixed account key.
static void test_phe_cipher_round_trip() {
    p::PheCipher cipher;
    CHECK(cipher.setup_defaults().has_value());

    const std::vector<uint8_t> account_key(p::PheCommon::PHE_ACCOUNT_KEY_LENGTH, 0x07);
    const std::vector<uint8_t> plaintext{'p', 'h', 'e', ' ', 's', 'e', 'c', 'r', 'e', 't'};

    auto ciphertext = cipher.encrypt(plaintext, account_key);
    CHECK(ciphertext.has_value());
    CHECK(*ciphertext != plaintext);

    auto recovered = cipher.decrypt(*ciphertext, account_key);
    CHECK(recovered.has_value());
    CHECK(*recovered == plaintext);
}

// Wrong account key fails to decrypt (unexpected{Error}, not a throw).
static void test_phe_cipher_wrong_key_is_error() {
    p::PheCipher cipher;
    CHECK(cipher.setup_defaults().has_value());

    const std::vector<uint8_t> key_a(p::PheCommon::PHE_ACCOUNT_KEY_LENGTH, 0x07);
    const std::vector<uint8_t> key_b(p::PheCommon::PHE_ACCOUNT_KEY_LENGTH, 0x08);
    const std::vector<uint8_t> plaintext{'d', 'a', 't', 'a'};

    auto ciphertext = cipher.encrypt(plaintext, key_a);
    CHECK(ciphertext.has_value());
    auto recovered = cipher.decrypt(*ciphertext, key_b);
    CHECK(!recovered.has_value());
}

int main() {
    test_phe_cipher_round_trip();
    test_phe_cipher_wrong_key_is_error();
    TEST_MAIN_RETURN();
}
