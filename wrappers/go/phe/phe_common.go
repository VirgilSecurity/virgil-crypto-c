package phe

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_phe -lvsc_phe_pb -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto
// #include <virgil/crypto/phe/vsce_phe_public.h>
import "C"


type PheCommon struct {
}

/*
* PHE elliptic curve point binary length
*/
func PheCommonGetPhePointLength () uint32 {
    return 65
}

/*
* PHE max password length
*/
func PheCommonGetPheMaxPasswordLength () uint32 {
    return 128
}

/*
* PHE server identifier length
*/
func PheCommonGetPheServerIdentifierLength () uint32 {
    return 32
}

/*
* PHE client identifier length
*/
func PheCommonGetPheClientIdentifierLength () uint32 {
    return 32
}

/*
* PHE account key length
*/
func PheCommonGetPheAccountKeyLength () uint32 {
    return 32
}

/*
* PHE private key length
*/
func PheCommonGetPhePrivateKeyLength () uint32 {
    return 32
}

/*
* PHE public key length
*/
func PheCommonGetPhePublicKeyLength () uint32 {
    return 65
}

/*
* PHE hash length
*/
func PheCommonGetPheHashLen () uint32 {
    return 32
}

/*
* Maximum data size to encrypt
*/
func PheCommonGetPheMaxEncryptLen () uint32 {
    return 1024 * 1024 - 64
}

/*
* Maximum data size to decrypt
*/
func PheCommonGetPheMaxDecryptLen () uint32 {
    return 1024 * 1024
}

/*
* Maximum data to authenticate
*/
func PheCommonGetPheMaxAuthLen () uint32 {
    return 1024
}
