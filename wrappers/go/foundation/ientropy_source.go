package foundation

import "C"

/*
* Defines generic interface for the entropy source.
*/
type IEntropySource interface {

    CContext

    /*
    * Defines that implemented source is strong.
    */
    IsStrong () bool

    /*
    * Gather entropy of the requested length.
    */
    Gather (len int32) []byte
}

