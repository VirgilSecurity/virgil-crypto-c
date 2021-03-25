package foundation

import "C"

/*
* Defines generic interface for the entropy source.
*/
type EntropySource interface {

    context

    /*
    * Defines that implemented source is strong.
    */
    IsStrong () bool

    /*
    * Gather entropy of the requested length.
    */
    Gather (len uint) ([]byte, error)

    /*
    * Release underlying C context.
    */
    Delete ()
}

