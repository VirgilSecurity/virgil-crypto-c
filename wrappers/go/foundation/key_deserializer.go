package foundation

import "C"

/*
* Public and private key deserialization from an interchangeable format.
*/
type KeyDeserializer interface {

    context

    /*
    * Deserialize given public key as an interchangeable format to the object.
    */
    DeserializePublicKey (publicKeyData []byte) (*RawPublicKey, error)

    /*
    * Deserialize given private key as an interchangeable format to the object.
    */
    DeserializePrivateKey (privateKeyData []byte) (*RawPrivateKey, error)

    /*
    * Release underlying C context.
    */
    Delete ()
}

