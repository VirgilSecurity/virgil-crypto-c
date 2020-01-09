package foundation

import "C"

/*
* Contains public part of the key.
*/
type PublicKey interface {

    context

    /*
    * Release underlying C context.
    */
    Delete ()
}

