package foundation

import "C"

/*
* Provide serialization of algorithm
*/
type IAlgInfoSerializer interface {

    CContext

    /*
    * Return buffer size enough to hold serialized algorithm.
    */
    SerializedLen (algInfo IAlgInfo) int32

    /*
    * Serialize algorithm info to buffer class.
    */
    Serialize (algInfo IAlgInfo) []byte
}

