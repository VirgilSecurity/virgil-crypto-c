package foundation

import "C"

/*
* Provide interface for data encryption.
*/
type IAuthDecrypt interface {

    ICipherAuthInfo

    /*
    * Decrypt given data.
    * If 'tag' is not given, then it will be taken from the 'enc'.
    */
    AuthDecrypt (data []byte, authData []byte, tag []byte) []byte

    /*
    * Calculate required buffer length to hold the authenticated decrypted data.
    */
    AuthDecryptedLen (dataLen int32) int32
}

