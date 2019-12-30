package foundation

import "C"

/*
* Provide data encryption and decryption interface with asymmetric keys.
*/
type KeyCipher interface {

    context

    /*
    * Check if algorithm can encrypt data with a given key.
    */
    CanEncrypt (publicKey PublicKey, dataLen uint) bool

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    EncryptedLen (publicKey PublicKey, dataLen uint) uint

    /*
    * Encrypt data with a given public key.
    */
    Encrypt (publicKey PublicKey, data []byte) ([]byte, error)

    /*
    * Check if algorithm can decrypt data with a given key.
    * However, success result of decryption is not guaranteed.
    */
    CanDecrypt (privateKey PrivateKey, dataLen uint) bool

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    DecryptedLen (privateKey PrivateKey, dataLen uint) uint

    /*
    * Decrypt given data.
    */
    Decrypt (privateKey PrivateKey, data []byte) ([]byte, error)

    /*
    * Release underlying C context.
    */
    Delete ()
}

