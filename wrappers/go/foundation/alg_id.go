package foundation

import "C"

/*
* Define implemented algorithm identificator.
*/
type AlgId int
const (
    ALG_ID_NONE AlgId = 0
    ALG_ID_SHA224 AlgId = 1
    ALG_ID_SHA256 AlgId = 2
    ALG_ID_SHA384 AlgId = 3
    ALG_ID_SHA512 AlgId = 4
    ALG_ID_KDF1 AlgId = 5
    ALG_ID_KDF2 AlgId = 6
    ALG_ID_RSA AlgId = 7
    ALG_ID_ECC AlgId = 8
    ALG_ID_ED25519 AlgId = 9
    ALG_ID_CURVE25519 AlgId = 10
    ALG_ID_SECP256R1 AlgId = 11
    ALG_ID_AES256_GCM AlgId = 12
    ALG_ID_AES256_CBC AlgId = 13
    ALG_ID_HMAC AlgId = 14
    ALG_ID_HKDF AlgId = 15
    ALG_ID_PKCS5_PBKDF2 AlgId = 16
    ALG_ID_PKCS5_PBES2 AlgId = 17
)
