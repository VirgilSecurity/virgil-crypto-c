package foundation

import "C"

/*
* Public and private key serialization to an interchangeable format.
*/
type KeySerializer interface {

    context

    /*
    * Calculate buffer size enough to hold serialized public key.
    *
    * Precondition: public key must be exportable.
    */
    SerializedPublicKeyLen (publicKey *RawPublicKey) uint32

    /*
    * Serialize given public key to an interchangeable format.
    *
    * Precondition: public key must be exportable.
    */
    SerializePublicKey (publicKey *RawPublicKey) ([]byte, error)

    /*
    * Calculate buffer size enough to hold serialized private key.
    *
    * Precondition: private key must be exportable.
    */
    SerializedPrivateKeyLen (privateKey *RawPrivateKey) uint32

    /*
    * Serialize given private key to an interchangeable format.
    *
    * Precondition: private key must be exportable.
    */
    SerializePrivateKey (privateKey *RawPrivateKey) ([]byte, error)

    /*
    * Release underlying C context.
    */
    Delete ()
}

