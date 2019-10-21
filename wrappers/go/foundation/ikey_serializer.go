package foundation

import "C"

/*
* Public and private key serialization to an interchangeable format.
*/
type IKeySerializer interface {

    CContext

    /*
    * Calculate buffer size enough to hold serialized public key.
    *
    * Precondition: public key must be exportable.
    */
    SerializedPublicKeyLen (publicKey RawPublicKey) int32

    /*
    * Serialize given public key to an interchangeable format.
    *
    * Precondition: public key must be exportable.
    */
    SerializePublicKey (publicKey RawPublicKey) []byte

    /*
    * Calculate buffer size enough to hold serialized private key.
    *
    * Precondition: private key must be exportable.
    */
    SerializedPrivateKeyLen (privateKey RawPrivateKey) int32

    /*
    * Serialize given private key to an interchangeable format.
    *
    * Precondition: private key must be exportable.
    */
    SerializePrivateKey (privateKey RawPrivateKey) []byte
}

