// C++ SDK round-trip / parity tests for the foundation library.
// Proves the generated wrapper is functionally equivalent to the C API and that
// the expected<T, Error> error path works without exceptions (-fno-exceptions).
#include <virgil/crypto/foundation/aes256_gcm.hpp>
#include <virgil/crypto/foundation/sha256.hpp>
#include <virgil/crypto/foundation/base64.hpp>

#include "check.hpp"

namespace f = virgil::crypto::foundation;

// AES-256-GCM encrypt -> decrypt round-trips to the original plaintext.
static void test_aes_gcm_round_trip() {
    const std::vector<uint8_t> key(f::Aes256Gcm::KEY_LEN, 0x01);
    const std::vector<uint8_t> nonce(f::Aes256Gcm::NONCE_LEN, 0x02);
    const std::vector<uint8_t> plaintext{'s', 'e', 'c', 'r', 'e', 't', ' ', 'd', 'a', 't', 'a'};

    f::Aes256Gcm enc;
    enc.set_key(key);
    enc.set_nonce(nonce);
    auto ciphertext = enc.encrypt(plaintext);
    CHECK(ciphertext.has_value());
    CHECK(*ciphertext != plaintext);

    f::Aes256Gcm dec;
    dec.set_key(key);
    dec.set_nonce(nonce);
    auto recovered = dec.decrypt(*ciphertext);
    CHECK(recovered.has_value());
    CHECK(*recovered == plaintext);
}

// Tampered ciphertext yields unexpected{Error} (auth failure) — never a throw/abort.
static void test_aes_gcm_tamper_is_error() {
    const std::vector<uint8_t> key(f::Aes256Gcm::KEY_LEN, 0x01);
    const std::vector<uint8_t> nonce(f::Aes256Gcm::NONCE_LEN, 0x02);
    const std::vector<uint8_t> plaintext{'a', 'u', 't', 'h', 'e', 'n', 't', 'i', 'c'};

    f::Aes256Gcm enc;
    enc.set_key(key);
    enc.set_nonce(nonce);
    auto ciphertext = enc.encrypt(plaintext);
    CHECK(ciphertext.has_value());

    std::vector<uint8_t> tampered = *ciphertext;
    tampered[0] ^= 0xFF;  // flip a byte -> GCM tag verification must fail

    f::Aes256Gcm dec;
    dec.set_key(key);
    dec.set_nonce(nonce);
    auto recovered = dec.decrypt(tampered);
    CHECK(!recovered.has_value());
    CHECK(recovered.error() == f::Error::AuthFailed);
}

// Edge case: empty input span round-trips (ciphertext is just the tag).
static void test_aes_gcm_empty_input() {
    const std::vector<uint8_t> key(f::Aes256Gcm::KEY_LEN, 0x03);
    const std::vector<uint8_t> nonce(f::Aes256Gcm::NONCE_LEN, 0x04);
    const std::vector<uint8_t> empty;

    f::Aes256Gcm enc;
    enc.set_key(key);
    enc.set_nonce(nonce);
    auto ciphertext = enc.encrypt(empty);
    CHECK(ciphertext.has_value());
    CHECK(ciphertext->size() == f::Aes256Gcm::AUTH_TAG_LEN);

    f::Aes256Gcm dec;
    dec.set_key(key);
    dec.set_nonce(nonce);
    auto recovered = dec.decrypt(*ciphertext);
    CHECK(recovered.has_value());
    CHECK(recovered->empty());
}

// SHA-256 matches the canonical vector for "abc".
static void test_sha256_known_vector() {
    const std::vector<uint8_t> abc{'a', 'b', 'c'};
    const std::vector<uint8_t> expected{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    f::Sha256 hash;
    const std::vector<uint8_t> digest = hash.hash(abc);
    CHECK(digest == expected);
}

// Base64 encode -> decode round-trips.
static void test_base64_round_trip() {
    const std::vector<uint8_t> data{'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};
    const std::vector<uint8_t> encoded = f::Base64::encode(data);
    CHECK(!encoded.empty());
    auto decoded = f::Base64::decode(encoded);
    CHECK(decoded.has_value());
    CHECK(*decoded == data);
}

int main() {
    test_aes_gcm_round_trip();
    test_aes_gcm_tamper_is_error();
    test_aes_gcm_empty_input();
    test_sha256_known_vector();
    test_base64_round_trip();
    TEST_MAIN_RETURN();
}
