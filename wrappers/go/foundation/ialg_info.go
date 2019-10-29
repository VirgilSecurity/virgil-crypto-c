package foundation

import "C"

/*
* Provide details about implemented algorithms.
*/
type IAlgInfo interface {

    context

    /*
    * Provide algorithm identificator.
    */
    AlgId () AlgId
}

