package foundation

import "C"

/*
* Provide data encryption and decryption interface with asymmetric keys.
*/
type IKeyCipher interface {

    IKeyAlg

    /*
    * Check if algorithm can encrypt data with a given key.
    */
    CanEncrypt (publicKey IPublicKey, dataLen int32) bool

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    EncryptedLen (publicKey IPublicKey, dataLen int32) int32

    /*
    * Encrypt data with a given public key.
    */
    Encrypt (publicKey IPublicKey, data []byte) []byte

    /*
    * Check if algorithm can decrypt data with a given key.
    * However, success result of decryption is not guaranteed.
    */
    CanDecrypt (privateKey IPrivateKey, dataLen int32) bool

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    DecryptedLen (privateKey IPrivateKey, dataLen int32) int32

    /*
    * Decrypt given data.
    */
    Decrypt (privateKey IPrivateKey, data []byte) []byte
}

