package foundation

import "C"

/*
* Provide interface to persist algorithm information and it parameters
* and then restore the algorithm from it.
*/
type IAlg interface {

    CContext

    /*
    * Provide algorithm identificator.
    */
    AlgId () AlgId

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    ProduceAlgInfo () IAlgInfo

    /*
    * Restore algorithm configuration from the given object.
    */
    RestoreAlgInfo (algInfo IAlgInfo)
}

