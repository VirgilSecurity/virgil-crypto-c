package foundation

import "C"

/*
* Provide details about implemented algorithms.
*/
type AlgInfo interface {

    context

    /*
    * Provide algorithm identificator.
    */
    AlgId () AlgId
}

