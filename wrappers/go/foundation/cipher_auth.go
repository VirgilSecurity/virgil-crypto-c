package foundation

import "C"

/*
* Mix-in interface that provides specific functionality to authenticated
* encryption and decryption (AEAD ciphers).
*/
type CipherAuth interface {

    context

    /*
    * Setup IV or nonce.
    */
    SetNonce (nonce []byte)

    /*
    * Set cipher encryption / decryption key.
    */
    SetKey (key []byte)

    /*
    * Start sequential encryption.
    */
    StartEncryption ()

    /*
    * Start sequential decryption.
    */
    StartDecryption ()

    /*
    * Process encryption or decryption of the given data chunk.
    */
    Update (data []byte) []byte

    /*
    * Return buffer length required to hold an output of the methods
    * "update" or "finish" in an current mode.
    * Pass zero length to define buffer length of the method "finish".
    */
    OutLen (dataLen uint) uint

    /*
    * Return buffer length required to hold an output of the methods
    * "update" or "finish" in an encryption mode.
    * Pass zero length to define buffer length of the method "finish".
    */
    EncryptedOutLen (dataLen uint) uint

    /*
    * Return buffer length required to hold an output of the methods
    * "update" or "finish" in an decryption mode.
    * Pass zero length to define buffer length of the method "finish".
    */
    DecryptedOutLen (dataLen uint) uint

    /*
    * Accomplish encryption or decryption process.
    */
    Finish () ([]byte, error)

    /*
    * Encrypt given data.
    * If 'tag' is not given, then it will written to the 'enc'.
    */
    AuthEncrypt (data []byte, authData []byte) ([]byte, []byte, error)

    /*
    * Calculate required buffer length to hold the authenticated encrypted data.
    */
    AuthEncryptedLen (dataLen uint) uint

    /*
    * Decrypt given data.
    * If 'tag' is not given, then it will be taken from the 'enc'.
    */
    AuthDecrypt (data []byte, authData []byte, tag []byte) ([]byte, error)

    /*
    * Calculate required buffer length to hold the authenticated decrypted data.
    */
    AuthDecryptedLen (dataLen uint) uint

    /*
    * Set additional data for for AEAD ciphers.
    */
    SetAuthData (authData []byte)

    /*
    * Accomplish an authenticated encryption and place tag separately.
    *
    * Note, if authentication tag should be added to an encrypted data,
    * method "finish" can be used.
    */
    FinishAuthEncryption () ([]byte, []byte, error)

    /*
    * Accomplish an authenticated decryption with explicitly given tag.
    *
    * Note, if authentication tag is a part of an encrypted data then,
    * method "finish" can be used for simplicity.
    */
    FinishAuthDecryption (tag []byte) ([]byte, error)
}

