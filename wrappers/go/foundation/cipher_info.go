package foundation

import "C"

/*
* Provides compile time knownledge about algorithm.
*/
type CipherInfo interface {

    context

    /*
    * Cipher nfonce length or IV length in bytes, or 0 if nonce is not required.
    */
    GetNonceLen () int

    /*
    * Cipher key length in bytes.
    */
    GetKeyLen () int

    /*
    * Cipher key length in bits.
    */
    GetKeyBitlen () int

    /*
    * Cipher block length in bytes.
    */
    GetBlockLen () int

    /*
    * Release underlying C context.
    */
    Delete ()
}

