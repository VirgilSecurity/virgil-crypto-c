package foundation

import "C"

/*
* Provide serialization of algorithm
*/
type IAlgInfoSerializer interface {

    context

    /*
    * Return buffer size enough to hold serialized algorithm.
    */
    SerializedLen (algInfo IAlgInfo) uint32

    /*
    * Serialize algorithm info to buffer class.
    */
    Serialize (algInfo IAlgInfo) []byte

    /*
    * Release underlying C context.
    */
    Delete ()
}

