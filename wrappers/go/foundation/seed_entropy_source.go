package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"


/*
* Deterministic entropy source that is based only on the given seed.
*/
type SeedEntropySource struct {
    cCtx *C.vscf_seed_entropy_source_t /*ct10*/
}
const (
    /*
    * The maximum length of the entropy requested at once.
    */
    SeedEntropySourceGatherLenMax uint32 = 48
)

/*
* Set a new seed as an entropy source.
*/
func (obj *SeedEntropySource) ResetSeed(seed []byte) {
    seedData := helperWrapData (seed)

    C.vscf_seed_entropy_source_reset_seed(obj.cCtx, seedData)

    return
}

/* Handle underlying C context. */
func (obj *SeedEntropySource) ctx() *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewSeedEntropySource() *SeedEntropySource {
    ctx := C.vscf_seed_entropy_source_new()
    obj := &SeedEntropySource {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSeedEntropySourceWithCtx(ctx *C.vscf_seed_entropy_source_t /*ct10*/) *SeedEntropySource {
    obj := &SeedEntropySource {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSeedEntropySourceCopy(ctx *C.vscf_seed_entropy_source_t /*ct10*/) *SeedEntropySource {
    obj := &SeedEntropySource {
        cCtx: C.vscf_seed_entropy_source_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *SeedEntropySource) Delete() {
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *SeedEntropySource) delete() {
    C.vscf_seed_entropy_source_delete(obj.cCtx)
}

/*
* Defines that implemented source is strong.
*/
func (obj *SeedEntropySource) IsStrong() bool {
    proxyResult := /*pr4*/C.vscf_seed_entropy_source_is_strong(obj.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Gather entropy of the requested length.
*/
func (obj *SeedEntropySource) Gather(len uint32) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(len))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.Delete()


    proxyResult := /*pr4*/C.vscf_seed_entropy_source_gather(obj.cCtx, (C.size_t)(len)/*pa10*/, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outBuf.getData() /* r7 */, nil
}
