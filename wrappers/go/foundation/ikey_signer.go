package foundation

import "C"

/*
* Provide an interface for signing and verifying data digest
* with asymmetric keys.
*/
type IKeySigner interface {

    context

    /*
    * Check if algorithm can sign data digest with a given key.
    */
    CanSign (privateKey IPrivateKey) bool

    /*
    * Return length in bytes required to hold signature.
    * Return zero if a given private key can not produce signatures.
    */
    SignatureLen (key IKey) uint32

    /*
    * Sign data digest with a given private key.
    */
    SignHash (privateKey IPrivateKey, hashId AlgId, digest []byte) ([]byte, error)

    /*
    * Check if algorithm can verify data digest with a given key.
    */
    CanVerify (publicKey IPublicKey) bool

    /*
    * Verify data digest with a given public key and signature.
    */
    VerifyHash (publicKey IPublicKey, hashId AlgId, digest []byte, signature []byte) bool
}

