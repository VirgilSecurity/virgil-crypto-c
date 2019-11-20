package phe

// #include <virgil/crypto/phe/vsce_phe_public.h>
import "C"


type PheCommon struct {
}
const (
    /*
    * PHE elliptic curve point binary length
    */
    PheCommonPhePointLength uint32 = 65
    /*
    * PHE max password length
    */
    PheCommonPheMaxPasswordLength uint32 = 128
    /*
    * PHE server identifier length
    */
    PheCommonPheServerIdentifierLength uint32 = 32
    /*
    * PHE client identifier length
    */
    PheCommonPheClientIdentifierLength uint32 = 32
    /*
    * PHE account key length
    */
    PheCommonPheAccountKeyLength uint32 = 32
    /*
    * PHE private key length
    */
    PheCommonPhePrivateKeyLength uint32 = 32
    /*
    * PHE public key length
    */
    PheCommonPhePublicKeyLength uint32 = 65
    /*
    * PHE hash length
    */
    PheCommonPheHashLen uint32 = 32
    /*
    * Maximum data size to encrypt
    */
    PheCommonPheMaxEncryptLen uint32 = 1024 * 1024 - 64
    /*
    * Maximum data size to decrypt
    */
    PheCommonPheMaxDecryptLen uint32 = 1024 * 1024
    /*
    * Maximum data to authenticate
    */
    PheCommonPheMaxAuthLen uint32 = 1024
)
