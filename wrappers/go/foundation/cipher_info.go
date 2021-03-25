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
    GetNonceLen () uint

    /*
    * Cipher key length in bytes.
    */
    GetKeyLen () uint

    /*
    * Cipher key length in bits.
    */
    GetKeyBitlen () uint

    /*
    * Cipher block length in bytes.
    */
    GetBlockLen () uint

    /*
    * Release underlying C context.
    */
    Delete ()
}

