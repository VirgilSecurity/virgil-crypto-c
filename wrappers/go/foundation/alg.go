package foundation

import "C"

/*
* Provide interface to persist algorithm information and it parameters
* and then restore the algorithm from it.
*/
type Alg interface {

    context

    /*
    * Provide algorithm identificator.
    */
    AlgId () AlgId

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    ProduceAlgInfo () (AlgInfo, error)

    /*
    * Restore algorithm configuration from the given object.
    */
    RestoreAlgInfo (algInfo AlgInfo) error

    /*
    * Release underlying C context.
    */
    Delete ()
}

