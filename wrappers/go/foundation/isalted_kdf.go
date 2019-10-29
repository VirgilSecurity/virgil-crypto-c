package foundation

import "C"

/*
* Provides interface to the key derivation function (KDF) algorithms
* that use salt and teration count.
*/
type ISaltedKdf interface {

    context

    /*
    * Prepare algorithm to derive new key.
    */
    Reset (salt []byte, iterationCount uint32)

    /*
    * Setup application specific information (optional).
    * Can be empty.
    */
    SetInfo (info []byte)
}

