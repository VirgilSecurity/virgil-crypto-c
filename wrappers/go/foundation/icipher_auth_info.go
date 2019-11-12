package foundation

import "C"

type ICipherAuthInfo interface {

    context

    /*
    * Defines authentication tag length in bytes.
    */
    GetAuthTagLen () uint32

    /*
    * Release underlying C context.
    */
    Delete ()
}

