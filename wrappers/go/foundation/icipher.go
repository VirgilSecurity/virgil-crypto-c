package foundation

import "C"

/*
* Provide interface for symmetric ciphers.
*/
type ICipher interface {

    IEncrypt

    IDecrypt

    ICipherInfo

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
    OutLen (dataLen int32) int32

    /*
    * Return buffer length required to hold an output of the methods
    * "update" or "finish" in an encryption mode.
    * Pass zero length to define buffer length of the method "finish".
    */
    EncryptedOutLen (dataLen int32) int32

    /*
    * Return buffer length required to hold an output of the methods
    * "update" or "finish" in an decryption mode.
    * Pass zero length to define buffer length of the method "finish".
    */
    DecryptedOutLen (dataLen int32) int32

    /*
    * Accomplish encryption or decryption process.
    */
    Finish () []byte
}

