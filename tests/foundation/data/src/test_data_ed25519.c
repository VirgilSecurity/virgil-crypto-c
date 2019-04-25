#include "test_data_ed25519.h"

const byte test_ed25519_RANDOM_BYTES[] = {
    0x4D, 0x43, 0x34, 0x43, 0x41, 0x51, 0x41, 0x77,
    0x42, 0x51, 0x59, 0x44, 0x4B, 0x32, 0x56, 0x77,
    0x42, 0x43, 0x49, 0x45, 0x49, 0x45, 0x73, 0x43,
    0x4C, 0x48, 0x4E, 0x50, 0x63, 0x58, 0x50, 0x2B,
};

const vsc_data_t test_ed25519_RANDOM = {
    test_ed25519_RANDOM_BYTES, sizeof(test_ed25519_RANDOM_BYTES)
};

const byte test_ed25519_PRIVATE_KEY_BYTES[] = {
    0x04, 0x20, 0x4D, 0x43, 0x34, 0x43, 0x41, 0x51,
    0x41, 0x77, 0x42, 0x51, 0x59, 0x44, 0x4B, 0x32,
    0x56, 0x77, 0x42, 0x43, 0x49, 0x45, 0x49, 0x45,
    0x73, 0x43, 0x4C, 0x48, 0x4E, 0x50, 0x63, 0x58,
    0x50, 0x2B
};

const vsc_data_t test_ed25519_PRIVATE_KEY = {
    test_ed25519_PRIVATE_KEY_BYTES, sizeof(test_ed25519_PRIVATE_KEY_BYTES)
};

const byte test_ed25519_PUBLIC_KEY_BYTES[] = {
    0xE7, 0x34, 0x9D, 0xD5, 0xEB, 0x23, 0x23, 0x37,
    0x66, 0xF3, 0x19, 0x2E, 0x2D, 0x9D, 0x4D, 0x26,
    0xD8, 0xA2, 0x67, 0x1D, 0x71, 0xE8, 0xAE, 0xD4,
    0x80, 0x53, 0xB4, 0x7F, 0x55, 0xF4, 0x70, 0x32
};

const vsc_data_t test_ed25519_PUBLIC_KEY = {
    test_ed25519_PUBLIC_KEY_BYTES, sizeof(test_ed25519_PUBLIC_KEY_BYTES)
};

const byte test_ed25519_MESSAGE_BYTES[] = {
    0x32, 0x37, 0x64, 0x32, 0x30, 0x39, 0x34, 0x30,
    0x65, 0x66, 0x30, 0x36, 0x30, 0x34, 0x64, 0x32,
    0x32, 0x39, 0x63, 0x32, 0x34, 0x65, 0x35, 0x61,
    0x35, 0x65, 0x62, 0x32, 0x30, 0x62, 0x31, 0x36
};

const vsc_data_t test_ed25519_MESSAGE = {
    test_ed25519_MESSAGE_BYTES, sizeof(test_ed25519_MESSAGE_BYTES)
};

const byte test_ed25519_MESSAGE_SHA256_DIGEST_BYTES[] = {
    0x36, 0x84, 0xa3, 0x16, 0xa7, 0x4a, 0xb3, 0x9b,
    0xd2, 0xc2, 0x9a, 0x2e, 0x86, 0x2f, 0x05, 0x79,
    0x5b, 0xe9, 0x49, 0xb2, 0x12, 0xc9, 0x20, 0xc4,
    0x3d, 0x21, 0xd4, 0xce, 0x9d, 0x41, 0x01, 0x6a
};

const vsc_data_t test_ed25519_MESSAGE_SHA256_DIGEST = {
    test_ed25519_MESSAGE_SHA256_DIGEST_BYTES, sizeof(test_ed25519_MESSAGE_SHA256_DIGEST_BYTES)
};

const byte test_ed25519_ENCRYPTED_MESSAGE_BYTES[] = {
    0x30, 0x81, 0xDB, 0x02, 0x01, 0x00, 0x30, 0x2A,
    0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03,
    0x21, 0x00, 0x85, 0x4F, 0x77, 0x97, 0x28, 0x30,
    0x06, 0xAE, 0x5E, 0x47, 0x4D, 0xFB, 0x61, 0x2C,
    0x41, 0xCB, 0xDB, 0xD1, 0x7C, 0xD3, 0xD3, 0x1B,
    0x21, 0x60, 0x21, 0x1E, 0x6B, 0x66, 0xD8, 0x87,
    0x12, 0xA4, 0x30, 0x16, 0x06, 0x07, 0x28, 0x81,
    0x8C, 0x71, 0x02, 0x05, 0x02, 0x30, 0x0B, 0x06,
    0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
    0x02, 0x02, 0x30, 0x3F, 0x30, 0x0B, 0x06, 0x09,
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
    0x02, 0x04, 0x30, 0xA7, 0xA6, 0xB8, 0xEF, 0x58,
    0x4C, 0x2B, 0x41, 0x9D, 0x7A, 0x43, 0xA8, 0x8A,
    0xBA, 0xA6, 0x56, 0x5E, 0xF6, 0x33, 0xB2, 0x80,
    0xE8, 0xEF, 0x3B, 0xA6, 0x19, 0x75, 0xF5, 0x36,
    0x16, 0x46, 0x50, 0x96, 0x54, 0x26, 0xF4, 0xC7,
    0xCC, 0x8B, 0x3E, 0x84, 0x21, 0x75, 0xE1, 0xEA,
    0x13, 0x19, 0x53, 0x30, 0x51, 0x30, 0x1D, 0x06,
    0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
    0x01, 0x2A, 0x04, 0x10, 0x28, 0xC8, 0xA5, 0xD1,
    0x3A, 0x37, 0xEF, 0x6C, 0x9A, 0x0A, 0x35, 0xAB,
    0x94, 0x27, 0xFB, 0x0F, 0x04, 0x30, 0x64, 0x40,
    0xC1, 0x28, 0x08, 0x7E, 0xD0, 0x91, 0xEF, 0x38,
    0x0E, 0xE3, 0xD4, 0xB8, 0x32, 0xC6, 0x62, 0x93,
    0x70, 0x0E, 0xA9, 0x65, 0xDD, 0xDD, 0x25, 0x4D,
    0x18, 0x83, 0x02, 0x68, 0x54, 0x8E, 0x09, 0xD2,
    0x4C, 0xFA, 0x08, 0xF4, 0x01, 0x58, 0x64, 0xE2,
    0xEE, 0xE1, 0xCF, 0x0B, 0x34, 0x77
};

const vsc_data_t test_ed25519_ENCRYPTED_MESSAGE = {
    test_ed25519_ENCRYPTED_MESSAGE_BYTES, sizeof(test_ed25519_ENCRYPTED_MESSAGE_BYTES)
};

const byte test_ed25519_SHA256_SIGNATURE_BYTES[] = {
    0xF2, 0x2B, 0xD5, 0xB9, 0x64, 0x8C, 0x90, 0x6B,
    0x19, 0x51, 0xDE, 0xED, 0x25, 0x6C, 0xE2, 0x95,
    0x11, 0x4B, 0x0B, 0x69, 0x9A, 0x06, 0x8F, 0xC5,
    0x2C, 0x15, 0x6B, 0x4F, 0xF3, 0xEF, 0xA5, 0xAE,
    0x03, 0x5E, 0x48, 0xF4, 0x47, 0xE9, 0xE2, 0x1F,
    0x6D, 0x63, 0x39, 0xE5, 0x50, 0x8F, 0x6B, 0x27,
    0x32, 0x71, 0xF7, 0x6F, 0xC9, 0x0D, 0xF9, 0x5C,
    0x0E, 0x96, 0x54, 0x36, 0x48, 0x2E, 0x14, 0x02,
};

const vsc_data_t test_ed25519_SHA256_SIGNATURE = {
    test_ed25519_SHA256_SIGNATURE_BYTES, sizeof(test_ed25519_SHA256_SIGNATURE_BYTES)
};

const byte test_ed25519_PUBLIC_KEY_PKCS8_DER_BYTES[] = {
    0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65,
    0x70, 0x03, 0x21, 0x00, 0xE7, 0x34, 0x9D, 0xD5,
    0xEB, 0x23, 0x23, 0x37, 0x66, 0xF3, 0x19, 0x2E,
    0x2D, 0x9D, 0x4D, 0x26, 0xD8, 0xA2, 0x67, 0x1D,
    0x71, 0xE8, 0xAE, 0xD4, 0x80, 0x53, 0xB4, 0x7F,
    0x55, 0xF4, 0x70, 0x32
};

const vsc_data_t test_ed25519_PUBLIC_KEY_PKCS8_DER = {
    test_ed25519_PUBLIC_KEY_PKCS8_DER_BYTES, sizeof(test_ed25519_PUBLIC_KEY_PKCS8_DER_BYTES)
};

const byte test_ed25519_PRIVATE_KEY_PKCS8_DER_BYTES[] = {
    0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
    0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    0x4D, 0x43, 0x34, 0x43, 0x41, 0x51, 0x41, 0x77,
    0x42, 0x51, 0x59, 0x44, 0x4B, 0x32, 0x56, 0x77,
    0x42, 0x43, 0x49, 0x45, 0x49, 0x45, 0x73, 0x43,
    0x4C, 0x48, 0x4E, 0x50, 0x63, 0x58, 0x50, 0x2B
};

const vsc_data_t test_ed25519_PRIVATE_KEY_PKCS8_DER = {
    test_ed25519_PRIVATE_KEY_PKCS8_DER_BYTES, sizeof(test_ed25519_PRIVATE_KEY_PKCS8_DER_BYTES)
};

const char test_ed25519_PUBLIC_KEY_PKCS8_PEM_STR[] = {
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEA5zSd1esjIzdm8xkuLZ1NJtiiZx1x6K7UgFO0f1X0cDI=\n"
    "-----END PUBLIC KEY-----"

};

const vsc_data_t test_ed25519_PUBLIC_KEY_PKCS8_PEM = {
    (const byte *)test_ed25519_PUBLIC_KEY_PKCS8_PEM_STR, sizeof(test_ed25519_PUBLIC_KEY_PKCS8_PEM_STR) - 1
};

const char test_ed25519_PRIVATE_KEY_PKCS8_PEM_STR[] = {
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VwBCIEIE1DNENBUUF3QlFZREsyVndCQ0lFSUVzQ0xITlBjWFAr\n"
    "-----END PRIVATE KEY-----"
};

const vsc_data_t test_ed25519_PRIVATE_KEY_PKCS8_PEM = {
    (const byte *)test_ed25519_PRIVATE_KEY_PKCS8_PEM_STR, sizeof(test_ed25519_PRIVATE_KEY_PKCS8_PEM_STR) - 1
};
