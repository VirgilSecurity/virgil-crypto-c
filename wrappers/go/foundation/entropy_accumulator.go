package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"

/*
* Implementation based on a simple entropy accumulator.
*/
type EntropyAccumulator struct {
    IEntropySource
    cCtx *C.vscf_entropy_accumulator_t /*ct10*/
}

func EntropyAccumulatorGetSourcesMax () uint32 {
    return 15
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (this EntropyAccumulator) SetupDefaults () {
    C.vscf_entropy_accumulator_setup_defaults(this.cCtx)

    return
}

/*
* Add given entropy source to the accumulator.
* Threshold defines minimum number of bytes that must be gathered
* from the source during accumulation.
*/
func (this EntropyAccumulator) AddSource (source IEntropySource, threshold uint32) {
    C.vscf_entropy_accumulator_add_source(this.cCtx, (*C.vscf_impl_t)(source.ctx()), (C.size_t)(threshold)/*pa10*/)

    return
}

/* Handle underlying C context. */
func (this EntropyAccumulator) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewEntropyAccumulator () *EntropyAccumulator {
    ctx := C.vscf_entropy_accumulator_new()
    return &EntropyAccumulator {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newEntropyAccumulatorWithCtx (ctx *C.vscf_entropy_accumulator_t /*ct10*/) *EntropyAccumulator {
    return &EntropyAccumulator {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newEntropyAccumulatorCopy (ctx *C.vscf_entropy_accumulator_t /*ct10*/) *EntropyAccumulator {
    return &EntropyAccumulator {
        cCtx: C.vscf_entropy_accumulator_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this EntropyAccumulator) close () {
    C.vscf_entropy_accumulator_delete(this.cCtx)
}

/*
* Defines that implemented source is strong.
*/
func (this EntropyAccumulator) IsStrong () bool {
    proxyResult := /*pr4*/C.vscf_entropy_accumulator_is_strong(this.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Gather entropy of the requested length.
*/
func (this EntropyAccumulator) Gather (len uint32) ([]byte, error) {
    outCount := C.ulong(len)
    outMemory := make([]byte, int(C.vsc_buffer_ctx_size() + outCount))
    outBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&outMemory[0]))
    outData := outMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(outBuf)
    C.vsc_buffer_use(outBuf, (*C.byte)(unsafe.Pointer(&outData[0])), outCount)
    defer C.vsc_buffer_delete(outBuf)


    proxyResult := /*pr4*/C.vscf_entropy_accumulator_gather(this.cCtx, (C.size_t)(len)/*pa10*/, outBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outData[0:C.vsc_buffer_len(outBuf)] /* r7 */, nil
}
