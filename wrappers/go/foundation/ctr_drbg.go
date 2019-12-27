package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Implementation of the RNG using deterministic random bit generators
* based on block ciphers in counter mode (CTR_DRBG from NIST SP800-90A).
* This class is thread-safe if the build option VSCF_MULTI_THREADING was enabled.
*/
type CtrDrbg struct {
    cCtx *C.vscf_ctr_drbg_t /*ct10*/
}
const (
    /*
    * The interval before reseed is performed by default.
    */
    CtrDrbgReseedInterval int = 10000
    /*
    * The amount of entropy used per seed by default.
    */
    CtrDrbgEntropyLen int = 48
)

func (obj *CtrDrbg) SetEntropySource(entropySource EntropySource) error {
    C.vscf_ctr_drbg_release_entropy_source(obj.cCtx)
                    proxyResult := C.vscf_ctr_drbg_use_entropy_source(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(entropySource.Ctx())))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }
                    runtime.KeepAlive(entropySource)
                    runtime.KeepAlive(obj)

    return nil
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (obj *CtrDrbg) SetupDefaults() error {
    proxyResult := /*pr4*/C.vscf_ctr_drbg_setup_defaults(obj.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

/*
* Force entropy to be gathered at the beginning of every call to
* the random() method.
* Note, use this if your entropy source has sufficient throughput.
*/
func (obj *CtrDrbg) EnablePredictionResistance() {
    C.vscf_ctr_drbg_enable_prediction_resistance(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Sets the reseed interval.
* Default value is reseed interval.
*/
func (obj *CtrDrbg) SetReseedInterval(interval int) {
    C.vscf_ctr_drbg_set_reseed_interval(obj.cCtx, (C.size_t)(interval)/*pa10*/)

    runtime.KeepAlive(obj)

    return
}

/*
* Sets the amount of entropy grabbed on each seed or reseed.
* The default value is entropy len.
*/
func (obj *CtrDrbg) SetEntropyLen(len int) {
    C.vscf_ctr_drbg_set_entropy_len(obj.cCtx, (C.size_t)(len)/*pa10*/)

    runtime.KeepAlive(obj)

    return
}

/* Handle underlying C context. */
func (obj *CtrDrbg) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewCtrDrbg() *CtrDrbg {
    ctx := C.vscf_ctr_drbg_new()
    obj := &CtrDrbg {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*CtrDrbg).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newCtrDrbgWithCtx(ctx *C.vscf_ctr_drbg_t /*ct10*/) *CtrDrbg {
    obj := &CtrDrbg {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*CtrDrbg).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newCtrDrbgCopy(ctx *C.vscf_ctr_drbg_t /*ct10*/) *CtrDrbg {
    obj := &CtrDrbg {
        cCtx: C.vscf_ctr_drbg_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*CtrDrbg).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *CtrDrbg) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *CtrDrbg) delete() {
    C.vscf_ctr_drbg_delete(obj.cCtx)
}

/*
* Generate random bytes.
* All RNG implementations must be thread-safe.
*/
func (obj *CtrDrbg) Random(dataLen int) ([]byte, error) {
    dataBuf, dataBufErr := bufferNewBuffer(int(dataLen))
    if dataBufErr != nil {
        return nil, dataBufErr
    }
    defer dataBuf.Delete()


    proxyResult := /*pr4*/C.vscf_ctr_drbg_random(obj.cCtx, (C.size_t)(dataLen)/*pa10*/, dataBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return dataBuf.getData() /* r7 */, nil
}

/*
* Retrieve new seed data from the entropy sources.
*/
func (obj *CtrDrbg) Reseed() error {
    proxyResult := /*pr4*/C.vscf_ctr_drbg_reseed(obj.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}
