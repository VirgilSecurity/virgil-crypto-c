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
    EncryptedLen (dataLen uint) uint

    /*
    * Precise length calculation of encrypted data.
    */
    PreciseEncryptedLen (dataLen uint) uint

    /*
    * Release underlying C context.
    */
    Delete ()
}

