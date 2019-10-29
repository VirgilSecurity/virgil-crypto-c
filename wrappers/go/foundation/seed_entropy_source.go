package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"

/*
* Deterministic entropy source that is based only on the given seed.
*/
type SeedEntropySource struct {
    IEntropySource
    cCtx *C.vscf_seed_entropy_source_t /*ct10*/
}

/*
* The maximum length of the entropy requested at once.
*/
func SeedEntropySourceGetGatherLenMax () uint32 {
    return 48
}

/*
* Set a new seed as an entropy source.
*/
func (this SeedEntropySource) ResetSeed (seed []byte) {
    seedData := C.vsc_data((*C.uint8_t)(&seed[0]), C.size_t(len(seed)))

    C.vscf_seed_entropy_source_reset_seed(this.cCtx, seedData)

    return
}

/* Handle underlying C context. */
func (this SeedEntropySource) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewSeedEntropySource () *SeedEntropySource {
    ctx := C.vscf_seed_entropy_source_new()
    return &SeedEntropySource {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSeedEntropySourceWithCtx (ctx *C.vscf_seed_entropy_source_t /*ct10*/) *SeedEntropySource {
    return &SeedEntropySource {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSeedEntropySourceCopy (ctx *C.vscf_seed_entropy_source_t /*ct10*/) *SeedEntropySource {
    return &SeedEntropySource {
        cCtx: C.vscf_seed_entropy_source_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this SeedEntropySource) close () {
    C.vscf_seed_entropy_source_delete(this.cCtx)
}

/*
* Defines that implemented source is strong.
*/
func (this SeedEntropySource) IsStrong () bool {
    proxyResult := /*pr4*/C.vscf_seed_entropy_source_is_strong(this.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Gather entropy of the requested length.
*/
func (this SeedEntropySource) Gather (len uint32) ([]byte, error) {
    outCount := C.ulong(len)
    outMemory := make([]byte, int(C.vsc_buffer_ctx_size() + outCount))
    outBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&outMemory[0]))
    outData := outMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(outBuf)
    C.vsc_buffer_use(outBuf, (*C.byte)(unsafe.Pointer(&outData[0])), outCount)
    defer C.vsc_buffer_delete(outBuf)


    proxyResult := /*pr4*/C.vscf_seed_entropy_source_gather(this.cCtx, (C.size_t)(len)/*pa10*/, outBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outData[0:C.vsc_buffer_len(outBuf)] /* r7 */, nil
}
