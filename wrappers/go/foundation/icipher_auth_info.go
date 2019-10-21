package foundation

import "C"

type ICipherAuthInfo interface {

    CContext

    /*
    * Defines authentication tag length in bytes.
    */
    getAuthTagLen () int32
}

