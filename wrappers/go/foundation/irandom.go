package foundation

import "C"

/*
* Common interface to get random data.
*/
type IRandom interface {

    context

    /*
    * Generate random bytes.
    * All RNG implementations must be thread-safe.
    */
    Random (dataLen uint32) ([]byte, error)

    /*
    * Retrieve new seed data from the entropy sources.
    */
    Reseed () error
}

