package foundation

import "C"

/*
* Provide details about implemented algorithms.
*/
type IAlgInfo interface {

    CContext

    /*
    * Provide algorithm identificator.
    */
    AlgId () AlgId
}

