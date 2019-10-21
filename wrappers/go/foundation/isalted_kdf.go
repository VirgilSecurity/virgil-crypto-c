package foundation

import "C"

/*
* Provides interface to the key derivation function (KDF) algorithms
* that use salt and teration count.
*/
type ISaltedKdf interface {

    IKdf

    /*
    * Prepare algorithm to derive new key.
    */
    Reset (salt []byte, iterationCount int32)

    /*
    * Setup application specific information (optional).
    * Can be empty.
    */
    SetInfo (info []byte)
}

