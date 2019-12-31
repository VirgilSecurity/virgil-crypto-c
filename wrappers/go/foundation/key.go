package foundation

import "C"

/*
* Basic key type.
*/
type Key interface {

    context

    /*
    * Algorithm identifier the key belongs to.
    */
    AlgId () AlgId

    /*
    * Return algorithm information that can be used for serialization.
    */
    AlgInfo () (AlgInfo, error)

    /*
    * Length of the key in bytes.
    */
    Len () uint

    /*
    * Length of the key in bits.
    */
    Bitlen () uint

    /*
    * Check that key is valid.
    * Note, this operation can be slow.
    */
    IsValid () bool

    /*
    * Release underlying C context.
    */
    Delete ()
}

