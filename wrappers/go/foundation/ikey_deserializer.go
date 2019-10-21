package foundation

import "C"

/*
* Public and private key deserialization from an interchangeable format.
*/
type IKeyDeserializer interface {

    CContext

    /*
    * Deserialize given public key as an interchangeable format to the object.
    */
    DeserializePublicKey (publicKeyData []byte) RawPublicKey

    /*
    * Deserialize given private key as an interchangeable format to the object.
    */
    DeserializePrivateKey (privateKeyData []byte) RawPrivateKey
}

