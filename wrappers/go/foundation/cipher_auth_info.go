package foundation

import "C"

type CipherAuthInfo interface {

    context

    /*
    * Defines authentication tag length in bytes.
    */
    GetAuthTagLen () uint

    /*
    * Release underlying C context.
    */
    Delete ()
}

