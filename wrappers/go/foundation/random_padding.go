package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Append a random number of padding bytes to a data.
*/
type RandomPadding struct {
    cCtx *C.vscf_random_padding_t /*ct10*/
}

func (obj *RandomPadding) SetRandom(random Random) {
    C.vscf_random_padding_release_random(obj.cCtx)
    C.vscf_random_padding_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

    runtime.KeepAlive(random)
    runtime.KeepAlive(obj)
}

/* Handle underlying C context. */
func (obj *RandomPadding) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewRandomPadding() *RandomPadding {
    ctx := C.vscf_random_padding_new()
    obj := &RandomPadding {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*RandomPadding).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRandomPaddingWithCtx(ctx *C.vscf_random_padding_t /*ct10*/) *RandomPadding {
    obj := &RandomPadding {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*RandomPadding).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRandomPaddingCopy(ctx *C.vscf_random_padding_t /*ct10*/) *RandomPadding {
    obj := &RandomPadding {
        cCtx: C.vscf_random_padding_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*RandomPadding).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *RandomPadding) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *RandomPadding) delete() {
    C.vscf_random_padding_delete(obj.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (obj *RandomPadding) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_random_padding_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (obj *RandomPadding) ProduceAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_random_padding_produce_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4.1 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (obj *RandomPadding) RestoreAlgInfo(algInfo AlgInfo) error {
    proxyResult := /*pr4*/C.vscf_random_padding_restore_alg_info(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(algInfo)

    return nil
}

/*
* Set new padding parameters.
*/
func (obj *RandomPadding) Configure(params *PaddingParams) {
    C.vscf_random_padding_configure(obj.cCtx, (*C.vscf_padding_params_t)(unsafe.Pointer(params.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(params)

    return
}

/*
* Return length in bytes of a data with a padding.
*/
func (obj *RandomPadding) PaddedDataLen(dataLen uint) uint {
    proxyResult := /*pr4*/C.vscf_random_padding_padded_data_len(obj.cCtx, (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Return an actual number of padding in bytes.
* Note, this method might be called right before "finish data processing".
*/
func (obj *RandomPadding) Len() uint {
    proxyResult := /*pr4*/C.vscf_random_padding_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Return a maximum number of padding in bytes.
*/
func (obj *RandomPadding) LenMax() uint {
    proxyResult := /*pr4*/C.vscf_random_padding_len_max(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Prepare the algorithm to process data.
*/
func (obj *RandomPadding) StartDataProcessing() {
    C.vscf_random_padding_start_data_processing(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Only data length is needed to produce padding later.
* Return data that should be further proceeded.
*/
func (obj *RandomPadding) ProcessData(data []byte) []byte {
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_random_padding_process_data(obj.cCtx, dataData)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Accomplish data processing and return padding.
*/
func (obj *RandomPadding) FinishDataProcessing() ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.Len() /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()


    proxyResult := /*pr4*/C.vscf_random_padding_finish_data_processing(obj.cCtx, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData() /* r7 */, nil
}

/*
* Prepare the algorithm to process padded data.
*/
func (obj *RandomPadding) StartPaddedDataProcessing() {
    C.vscf_random_padding_start_padded_data_processing(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Process padded data.
* Return filtered data without padding.
*/
func (obj *RandomPadding) ProcessPaddedData(data []byte) []byte {
    outBuf, outBufErr := newBuffer(int(len(data)))
    if outBufErr != nil {
        return nil
    }
    defer outBuf.delete()
    dataData := helperWrapData (data)

    C.vscf_random_padding_process_padded_data(obj.cCtx, dataData, outBuf.ctx)

    runtime.KeepAlive(obj)

    return outBuf.getData() /* r7 */
}

/*
* Return length in bytes required hold output of the method
* "finish padded data processing".
*/
func (obj *RandomPadding) FinishPaddedDataProcessingOutLen() uint {
    proxyResult := /*pr4*/C.vscf_random_padding_finish_padded_data_processing_out_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Accomplish padded data processing and return left data without a padding.
*/
func (obj *RandomPadding) FinishPaddedDataProcessing() ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.FinishPaddedDataProcessingOutLen() /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()


    proxyResult := /*pr4*/C.vscf_random_padding_finish_padded_data_processing(obj.cCtx, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData() /* r7 */, nil
}
