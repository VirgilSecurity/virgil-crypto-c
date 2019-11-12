package foundation

import "C"

/*
* Defines generic interface for the entropy source.
*/
type IEntropySource interface {

    context

    /*
    * Defines that implemented source is strong.
    */
    IsStrong () bool

    /*
    * Gather entropy of the requested length.
    */
    Gather (len uint32) ([]byte, error)

    /*
    * Release underlying C context.
    */
    Delete ()
}

