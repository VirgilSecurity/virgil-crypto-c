package foundation

import "C"

/*
* Provides interface to the stateless MAC (message authentication code) algorithms.
*/
type Mac interface {

    context

    /*
    * Size of the digest (mac output) in bytes.
    */
    DigestLen () uint32

    /*
    * Calculate MAC over given data.
    */
    Mac (key []byte, data []byte) []byte

    /*
    * Start a new MAC.
    */
    Start (key []byte)

    /*
    * Add given data to the MAC.
    */
    Update (data []byte)

    /*
    * Accomplish MAC and return it's result (a message digest).
    */
    Finish () []byte

    /*
    * Prepare to authenticate a new message with the same key
    * as the previous MAC operation.
    */
    Reset ()

    /*
    * Release underlying C context.
    */
    Delete ()
}

