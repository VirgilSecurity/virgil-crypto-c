package phe

// #include <virgil/crypto/phe/vsce_phe_public.h>
import "C"


type PheCommon struct {
}
const (
    /*
    * PHE elliptic curve point binary length
    */
    PheCommonPhePointLength uint = 65
    /*
    * PHE max password length
    */
    PheCommonPheMaxPasswordLength uint = 128
    /*
    * PHE server identifier length
    */
    PheCommonPheServerIdentifierLength uint = 32
    /*
    * PHE client identifier length
    */
    PheCommonPheClientIdentifierLength uint = 32
    /*
    * PHE account key length
    */
    PheCommonPheAccountKeyLength uint = 32
    /*
    * PHE private key length
    */
    PheCommonPhePrivateKeyLength uint = 32
    /*
    * PHE public key length
    */
    PheCommonPhePublicKeyLength uint = 65
    /*
    * PHE hash length
    */
    PheCommonPheHashLen uint = 32
    /*
    * Maximum data size to encrypt
    */
    PheCommonPheMaxEncryptLen uint = 1024 * 1024 - 64
    /*
    * Maximum data size to decrypt
    */
    PheCommonPheMaxDecryptLen uint = 1024 * 1024
    /*
    * Maximum data to authenticate
    */
    PheCommonPheMaxAuthLen uint = 1024
)
