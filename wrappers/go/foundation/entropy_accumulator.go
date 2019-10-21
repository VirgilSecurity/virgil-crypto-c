package foundation

// #cgo CFLAGS: -I${SRCDIR}/../../../build/library/foundation/include/virgil/crypto/foundation
// #cgo CFLAGS: -I${SRCDIR}/../../../library/foundation/include/virgil/crypto/foundation
// #cgo LDFLAGS: -L${SRCDIR}/../../java/binaries/linux/lib -lvscf_foundation_java
// #include <vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Implementation based on a simple entropy accumulator.
*/
type EntropyAccumulator struct {
    IEntropySource
    ctx *C.vscf_impl_t
}

func (this EntropyAccumulator) getSourcesMax () int32 {
    return 15
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (this EntropyAccumulator) SetupDefaults () {
    C.vscf_entropy_accumulator_setup_defaults(this.ctx)
}

/*
* Add given entropy source to the accumulator.
* Threshold defines minimum number of bytes that must be gathered
* from the source during accumulation.
*/
func (this EntropyAccumulator) AddSource (source IEntropySource, threshold int32) {
    C.vscf_entropy_accumulator_add_source(this.ctx, source.Ctx(), threshold)
}

/* Handle underlying C context. */
func (this EntropyAccumulator) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewEntropyAccumulator () *EntropyAccumulator {
    ctx := C.vscf_entropy_accumulator_new()
    return &EntropyAccumulator {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewEntropyAccumulatorWithCtx (ctx *C.vscf_impl_t) *EntropyAccumulator {
    return &EntropyAccumulator {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewEntropyAccumulatorCopy (ctx *C.vscf_impl_t) *EntropyAccumulator {
    return &EntropyAccumulator {
        ctx: C.vscf_entropy_accumulator_shallow_copy(ctx),
    }
}

/*
* Defines that implemented source is strong.
*/
func (this EntropyAccumulator) IsStrong () bool {
    proxyResult := C.vscf_entropy_accumulator_is_strong(this.ctx)

    return proxyResult //r9
}

/*
* Gather entropy of the requested length.
*/
func (this EntropyAccumulator) Gather (len int32) []byte {
    outCount := len
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    proxyResult := C.vscf_entropy_accumulator_gather(this.ctx, len, outBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */
}
