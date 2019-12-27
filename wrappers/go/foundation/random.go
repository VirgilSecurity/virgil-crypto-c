package foundation

import "C"

/*
* Common interface to get random data.
*/
type Random interface {

    context

    /*
    * Generate random bytes.
    * All RNG implementations must be thread-safe.
    */
    Random (dataLen int) ([]byte, error)

    /*
    * Retrieve new seed data from the entropy sources.
    */
    Reseed () error

    /*
    * Release underlying C context.
    */
    Delete ()
}

