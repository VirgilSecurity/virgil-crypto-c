package foundation

import "C"

/*
* Provide interface for data encryption.
*/
type IDecrypt interface {

    CContext

    /*
    * Decrypt given data.
    */
    Decrypt (data []byte) []byte

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    DecryptedLen (dataLen int32) int32
}

