package foundation

import "C"

/*
* Provides interface to the key derivation function (KDF) algorithms.
*/
type IKdf interface {

    CContext

    /*
    * Derive key of the requested length from the given data.
    */
    Derive (data []byte, keyLen int32) []byte
}

