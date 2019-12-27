package foundation

import "C"

/*
* Provide serialization of algorithm
*/
type AlgInfoSerializer interface {

    context

    /*
    * Return buffer size enough to hold serialized algorithm.
    */
    SerializedLen (algInfo AlgInfo) int

    /*
    * Serialize algorithm info to buffer class.
    */
    Serialize (algInfo AlgInfo) []byte

    /*
    * Release underlying C context.
    */
    Delete ()
}

