package foundation

import "C"

/*
* Provides compile time knownledge about algorithm.
*/
type ICipherInfo interface {

    context

    /*
    * Cipher nfonce length or IV length in bytes, or 0 if nonce is not required.
    */
    GetNonceLen () uint32

    /*
    * Cipher key length in bytes.
    */
    GetKeyLen () uint32

    /*
    * Cipher key length in bits.
    */
    GetKeyBitlen () uint32

    /*
    * Cipher block length in bytes.
    */
    GetBlockLen () uint32
}

