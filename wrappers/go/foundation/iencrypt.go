package foundation

import "C"

/*
* Provide interface for data encryption.
*/
type IEncrypt interface {

    CContext

    /*
    * Encrypt given data.
    */
    Encrypt (data []byte) []byte

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    EncryptedLen (dataLen int32) int32

    /*
    * Precise length calculation of encrypted data.
    */
    PreciseEncryptedLen (dataLen int32) int32
}

