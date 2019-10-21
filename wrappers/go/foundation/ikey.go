package foundation

import "C"

/*
* Basic key type.
*/
type IKey interface {

    CContext

    /*
    * Algorithm identifier the key belongs to.
    */
    AlgId () AlgId

    /*
    * Return algorithm information that can be used for serialization.
    */
    AlgInfo () IAlgInfo

    /*
    * Length of the key in bytes.
    */
    Len () int32

    /*
    * Length of the key in bits.
    */
    Bitlen () int32

    /*
    * Check that key is valid.
    * Note, this operation can be slow.
    */
    IsValid () bool
}

