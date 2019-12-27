package foundation

import "C"

type CipherAuthInfo interface {

    context

    /*
    * Defines authentication tag length in bytes.
    */
    GetAuthTagLen () int

    /*
    * Release underlying C context.
    */
    Delete ()
}

