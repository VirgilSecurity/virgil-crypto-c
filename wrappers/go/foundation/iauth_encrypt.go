package foundation

import "C"

/*
* Provide interface for authenticated data encryption.
*/
type IAuthEncrypt interface {

    ICipherAuthInfo

    /*
    * Encrypt given data.
    * If 'tag' is not given, then it will written to the 'enc'.
    */
    AuthEncrypt (data []byte, authData []byte) ([]byte, []byte)

    /*
    * Calculate required buffer length to hold the authenticated encrypted data.
    */
    AuthEncryptedLen (dataLen int32) int32
}

