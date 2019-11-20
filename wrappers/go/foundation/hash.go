package foundation

import "C"

/*
* Provides interface to the hashing (messege digest) algorithms.
*/
type Hash interface {

    context

    /*
    * Length of the digest (hashing output) in bytes.
    */
    GetDigestLen () uint32

    /*
    * Block length of the digest function in bytes.
    */
    GetBlockLen () uint32

    /*
    * Calculate hash over given data.
    */
    Hash (data []byte) []byte

    /*
    * Start a new hashing.
    */
    Start ()

    /*
    * Add given data to the hash.
    */
    Update (data []byte)

    /*
    * Accompilsh hashing and return it's result (a message digest).
    */
    Finish () []byte

    /*
    * Release underlying C context.
    */
    Delete ()
}

