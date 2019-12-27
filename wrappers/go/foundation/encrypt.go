package foundation

import "C"

/*
* Provide interface for data encryption.
*/
type Encrypt interface {

    context

    /*
    * Encrypt given data.
    */
    Encrypt (data []byte) ([]byte, error)

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    EncryptedLen (dataLen int) int

    /*
    * Precise length calculation of encrypted data.
    */
    PreciseEncryptedLen (dataLen int) int

    /*
    * Release underlying C context.
    */
    Delete ()
}

