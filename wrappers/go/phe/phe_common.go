package phe

// #include <virgil/crypto/phe/vsce_phe_public.h>
import "C"


type PheCommon struct {
}
const (
    /*
    * PHE elliptic curve point binary length
    */
    PheCommonPhePointLength int = 65
    /*
    * PHE max password length
    */
    PheCommonPheMaxPasswordLength int = 128
    /*
    * PHE server identifier length
    */
    PheCommonPheServerIdentifierLength int = 32
    /*
    * PHE client identifier length
    */
    PheCommonPheClientIdentifierLength int = 32
    /*
    * PHE account key length
    */
    PheCommonPheAccountKeyLength int = 32
    /*
    * PHE private key length
    */
    PheCommonPhePrivateKeyLength int = 32
    /*
    * PHE public key length
    */
    PheCommonPhePublicKeyLength int = 65
    /*
    * PHE hash length
    */
    PheCommonPheHashLen int = 32
    /*
    * Maximum data size to encrypt
    */
    PheCommonPheMaxEncryptLen int = 1024 * 1024 - 64
    /*
    * Maximum data size to decrypt
    */
    PheCommonPheMaxDecryptLen int = 1024 * 1024
    /*
    * Maximum data to authenticate
    */
    PheCommonPheMaxAuthLen int = 1024
)
