package foundation

// #cgo CFLAGS: -I${SRCDIR}/../../../build/library/foundation/include/virgil/crypto/foundation
// #cgo CFLAGS: -I${SRCDIR}/../../../library/foundation/include/virgil/crypto/foundation
// #cgo LDFLAGS: -L${SRCDIR}/../../java/binaries/linux/lib -lvscf_foundation_java
// #include <vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Deterministic entropy source that is based only on the given seed.
*/
type SeedEntropySource struct {
    IEntropySource
    ctx *C.vscf_impl_t
}

/*
* The maximum length of the entropy requested at once.
*/
func (this SeedEntropySource) getGatherLenMax () int32 {
    return 48
}

/*
* Set a new seed as an entropy source.
*/
func (this SeedEntropySource) ResetSeed (seed []byte) {
    C.vscf_seed_entropy_source_reset_seed(this.ctx, WrapData(seed))
}

/* Handle underlying C context. */
func (this SeedEntropySource) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewSeedEntropySource () *SeedEntropySource {
    ctx := C.vscf_seed_entropy_source_new()
    return &SeedEntropySource {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewSeedEntropySourceWithCtx (ctx *C.vscf_impl_t) *SeedEntropySource {
    return &SeedEntropySource {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewSeedEntropySourceCopy (ctx *C.vscf_impl_t) *SeedEntropySource {
    return &SeedEntropySource {
        ctx: C.vscf_seed_entropy_source_shallow_copy(ctx),
    }
}

/*
* Defines that implemented source is strong.
*/
func (this SeedEntropySource) IsStrong () bool {
    proxyResult := C.vscf_seed_entropy_source_is_strong(this.ctx)

    return proxyResult //r9
}

/*
* Gather entropy of the requested length.
*/
func (this SeedEntropySource) Gather (len int32) []byte {
    outCount := len
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    proxyResult := C.vscf_seed_entropy_source_gather(this.ctx, len, outBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */
}
