package foundation

import "C"

/*
* Provide data encryption and decryption interface with asymmetric keys.
*/
type IKeyCipher interface {

    context

    /*
    * Check if algorithm can encrypt data with a given key.
    */
    CanEncrypt (publicKey IPublicKey, dataLen uint32) bool

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    EncryptedLen (publicKey IPublicKey, dataLen uint32) uint32

    /*
    * Encrypt data with a given public key.
    */
    Encrypt (publicKey IPublicKey, data []byte) ([]byte, error)

    /*
    * Check if algorithm can decrypt data with a given key.
    * However, success result of decryption is not guaranteed.
    */
    CanDecrypt (privateKey IPrivateKey, dataLen uint32) bool

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    DecryptedLen (privateKey IPrivateKey, dataLen uint32) uint32

    /*
    * Decrypt given data.
    */
    Decrypt (privateKey IPrivateKey, data []byte) ([]byte, error)

    /*
    * Release underlying C context.
    */
    Delete ()
}

