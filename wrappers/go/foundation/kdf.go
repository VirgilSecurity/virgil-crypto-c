package foundation

import "C"

/*
* Provides interface to the key derivation function (KDF) algorithms.
*/
type Kdf interface {

    context

    /*
    * Derive key of the requested length from the given data.
    */
    Derive (data []byte, keyLen uint) []byte

    /*
    * Release underlying C context.
    */
    Delete ()
}

