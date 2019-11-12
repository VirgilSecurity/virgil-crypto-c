package foundation

import "C"

/*
* Provide interface for authenticated data encryption.
*/
type IAuthEncrypt interface {

    context

    /*
    * Encrypt given data.
    * If 'tag' is not given, then it will written to the 'enc'.
    */
    AuthEncrypt (data []byte, authData []byte) ([]byte, []byte, error)

    /*
    * Calculate required buffer length to hold the authenticated encrypted data.
    */
    AuthEncryptedLen (dataLen uint32) uint32

    /*
    * Release underlying C context.
    */
    Delete ()
}

