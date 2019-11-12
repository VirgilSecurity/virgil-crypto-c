package foundation

import "C"

/*
* Basic key type.
*/
type IKey interface {

    context

    /*
    * Algorithm identifier the key belongs to.
    */
    AlgId () AlgId

    /*
    * Return algorithm information that can be used for serialization.
    */
    AlgInfo () (IAlgInfo, error)

    /*
    * Length of the key in bytes.
    */
    Len () uint32

    /*
    * Length of the key in bits.
    */
    Bitlen () uint32

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

