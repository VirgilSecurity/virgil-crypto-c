package foundation

import "C"

/*
* Provide an interface for signing and verifying data digest
* with asymmetric keys.
*/
type KeySigner interface {

    context

    /*
    * Check if algorithm can sign data digest with a given key.
    */
    CanSign (privateKey PrivateKey) bool

    /*
    * Return length in bytes required to hold signature.
    * Return zero if a given private key can not produce signatures.
    */
    SignatureLen (privateKey PrivateKey) uint

    /*
    * Sign data digest with a given private key.
    */
    SignHash (privateKey PrivateKey, hashId AlgId, digest []byte) ([]byte, error)

    /*
    * Check if algorithm can verify data digest with a given key.
    */
    CanVerify (publicKey PublicKey) bool

    /*
    * Verify data digest with a given public key and signature.
    */
    VerifyHash (publicKey PublicKey, hashId AlgId, digest []byte, signature []byte) bool

    /*
    * Release underlying C context.
    */
    Delete ()
}

