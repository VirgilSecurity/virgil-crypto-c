package foundation

import "C"

/*
* Provide an interface to add and remove data padding.
*/
type Padding interface {

    context

    /*
    * Set new padding parameters.
    */
    Configure (params *PaddingParams)

    /*
    * Return length in bytes of a data with a padding.
    */
    PaddedDataLen (dataLen int) int

    /*
    * Return an actual number of padding in bytes.
    * Note, this method might be called right before "finish data processing".
    */
    Len () int

    /*
    * Return a maximum number of padding in bytes.
    */
    LenMax () int

    /*
    * Prepare the algorithm to process data.
    */
    StartDataProcessing ()

    /*
    * Only data length is needed to produce padding later.
    * Return data that should be further proceeded.
    */
    ProcessData (data []byte) []byte

    /*
    * Accomplish data processing and return padding.
    */
    FinishDataProcessing () ([]byte, error)

    /*
    * Prepare the algorithm to process padded data.
    */
    StartPaddedDataProcessing ()

    /*
    * Process padded data.
    * Return filtered data without padding.
    */
    ProcessPaddedData (data []byte) []byte

    /*
    * Return length in bytes required hold output of the method
    * "finish padded data processing".
    */
    FinishPaddedDataProcessingOutLen () int

    /*
    * Accomplish padded data processing and return left data without a padding.
    */
    FinishPaddedDataProcessing () ([]byte, error)

    /*
    * Release underlying C context.
    */
    Delete ()
}

