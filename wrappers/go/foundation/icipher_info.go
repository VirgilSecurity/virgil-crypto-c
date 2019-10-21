package foundation

import "C"

/*
* Provides compile time knownledge about algorithm.
*/
type ICipherInfo interface {

    CContext

    /*
    * Cipher nfonce length or IV length in bytes, or 0 if nonce is not required.
    */
    getNonceLen () int32

    /*
    * Cipher key length in bytes.
    */
    getKeyLen () int32

    /*
    * Cipher key length in bits.
    */
    getKeyBitlen () int32

    /*
    * Cipher block length in bytes.
    */
    getBlockLen () int32
}

